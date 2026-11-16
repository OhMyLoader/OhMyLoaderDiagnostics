//! Multi-source GC-root BFS: shortest strong-reference paths, plus path enumeration and formatting.
//!
//! The wavefront is parallel: expanding a node is a pure structural read that depends on no BFS state, so
//! a batch of nodes is expanded by worker threads and the resulting edges are then merged serially in FIFO
//! order through `visit_edge`, including the `stop_depth` and `targets_found` updates. Expansion order and
//! merge order are the single-threaded order, so every `dist` and predecessor list is identical and the
//! output matches the historical baseline byte for byte.
//!
//! Performance:
//! - data expansion depends on (flattened fields, reference semantics, `FinalReference` semantics) is
//!   computed once per class before the BFS starts (`ExpPre`, shared read-only as `Arc`) instead of being
//!   rebuilt per batch per thread;
//! - `dist` and predecessors live in one state table (`NodeState`), so merging hashes each edge once through
//!   the entry API, and edges to already-visited nodes skip the Heap membership check.

use super::hash::{HashMap, new_map};
use std::sync::Arc;
use std::thread;

use super::model::{FField, Heap};
use super::{Config, MAX_PREDS};

/// Below this batch size the work stays on one thread; the spawn cost would exceed it.
const MIN_PARALLEL_BATCH: usize = 4096;
/// Nodes per batch, which bounds the peak memory of the edge buffers.
const BATCH: usize = 1 << 17;

/// Derived expansion data, computed once and shared read-only across threads.
pub(crate) struct ExpPre {
    /// Class id → flattened fields (own class first, superclass chain after) plus reference semantics.
    by_class: HashMap<u64, ClassExp>,
}

/// One class's derived expansion data, so a node costs a single hash lookup.
struct ClassExp {
    flat: Arc<Vec<FField>>,
    ref_like: bool,
    final_ref: bool,
}

impl ExpPre {
    pub(crate) fn build(h: &Heap) -> ExpPre {
        let flat = h.flatten_all();
        // One shared cache per classification, so walking the class chain does not repeat per class.
        let mut ref_like: HashMap<u64, bool> = new_map();
        let mut final_ref: HashMap<u64, bool> = new_map();
        let mut by_class: HashMap<u64, ClassExp> = new_map();
        for &cid in &h.classes_order {
            let rl = h.is_reference_like(&mut ref_like, cid);
            let fr = h.is_final_reference(&mut final_ref, cid);
            by_class.insert(
                cid,
                ClassExp {
                    flat: flat.get(&cid).cloned().unwrap_or_default(),
                    ref_like: rl,
                    final_ref: fr,
                },
            );
        }
        ExpPre { by_class }
    }
}

/// BFS node state: distance plus the predecessors at that distance, in FIFO order.
struct NodeState {
    dist: u32,
    preds: Vec<(u64, EdgeLabel)>,
}

pub(crate) struct Bfs {
    state: HashMap<u64, NodeState>,
    queue: Vec<u64>,
    head: usize,
    target_ids: std::collections::BTreeSet<u64>,
    targets_found: usize,
    stop_depth: u32,
}

impl Bfs {
    pub(crate) fn reachable(&self, id: &u64) -> bool {
        self.state.contains_key(id)
    }
    pub(crate) fn dist_of(&self, id: &u64) -> Option<u32> {
        self.state.get(id).map(|s| s.dist)
    }
    pub(crate) fn visited(&self) -> usize {
        self.state.len()
    }
}

/// BFS edge label. The hot path allocates no `String`: field and static names are stored as string ids.
#[derive(Clone)]
pub(crate) enum EdgeLabel {
    Class,
    ClassLoader,
    Superclass,
    ConstantPool,
    /// A class static field, by name string id.
    Static(u64),
    /// An instance field, by name string id.
    Field(u64),
    /// An array index.
    Index(u32),
    /// A root label, only during seeding, so the allocation here is bounded by the root count.
    Root(String),
}

impl EdgeLabel {
    pub(crate) fn text(&self, h: &Heap) -> String {
        match self {
            EdgeLabel::Class => "class".into(),
            EdgeLabel::ClassLoader => "classLoader".into(),
            EdgeLabel::Superclass => "superclass".into(),
            EdgeLabel::ConstantPool => "constantPool".into(),
            EdgeLabel::Static(id) => {
                format!("static {}", h.strings.get(id).map(|s| &**s).unwrap_or("?"))
            }
            EdgeLabel::Field(id) => h
                .strings
                .get(id)
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("<field:{id}>")),
            EdgeLabel::Index(i) => format!("[{i}]"),
            EdgeLabel::Root(s) => s.clone(),
        }
    }
}

impl Bfs {
    fn visit_edge(&mut self, h: &Heap, from: u64, to: u64, label: EdgeLabel, from_dist: u32) {
        let nd = from_dist + 1;
        if nd > self.stop_depth {
            return;
        }
        // Branch on the state table first: a node already in it has passed the membership check before, so
        // the common path is the same-distance predecessor merge. Only a first-time node pays the two Heap
        // lookups.
        match self.state.entry(to) {
            std::collections::hash_map::Entry::Vacant(e) => {
                if !h.classes.contains_key(&to) && !h.objects.contains_key(&to) {
                    return;
                }
                e.insert(NodeState {
                    dist: nd,
                    preds: vec![(from, label)],
                });
                self.queue.push(to);
                if self.target_ids.contains(&to) {
                    self.targets_found += 1;
                    if self.targets_found == self.target_ids.len() {
                        self.stop_depth = self
                            .target_ids
                            .iter()
                            .filter_map(|id| self.state.get(id).map(|s| s.dist))
                            .max()
                            .unwrap_or(u32::MAX);
                    }
                }
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let s = e.get_mut();
                if s.dist == nd && s.preds.len() < MAX_PREDS {
                    s.preds.push((from, label));
                }
            }
        }
    }
}

fn add_root(id: u64, label: &str, state: &mut HashMap<u64, NodeState>, queue: &mut Vec<u64>) {
    if id == 0 {
        return;
    }
    match state.entry(id) {
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(NodeState {
                dist: 1,
                preds: vec![(0, EdgeLabel::Root(label.to_string()))],
            });
            queue.push(id);
        }
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let s = e.get_mut();
            if s.dist == 1 && s.preds.len() < MAX_PREDS {
                s.preds.push((0, EdgeLabel::Root(label.to_string())));
            }
        }
    }
}

/// Expands one node into its structural edges, in the order the single-threaded version would call
/// `visit_edge`. Expansion reads only the Heap, the config, and `ExpPre` — never `dist` — which is what
/// makes it safe to run on several threads.
pub(crate) fn expand_node(h: &Heap, cfg: &Config, u: u64, pre: &ExpPre) -> Vec<(u64, EdgeLabel)> {
    let mut edges: Vec<(u64, EdgeLabel)> = Vec::new();
    if let Some(meta) = h.classes.get(&u) {
        let loader = meta.loader_id;
        let sup = meta.super_id;
        if loader != 0 {
            edges.push((loader, EdgeLabel::ClassLoader));
        }
        if sup != 0 {
            edges.push((sup, EdgeLabel::Superclass));
        }
        for r in &meta.cp_refs {
            if *r != 0 {
                edges.push((*r, EdgeLabel::ConstantPool));
            }
        }
        for (name_id, value) in &meta.statics {
            if *value != 0 {
                edges.push((*value, EdgeLabel::Static(*name_id)));
            }
        }
        return edges;
    }
    let Some(e) = h.objects.get(&u) else {
        return edges;
    };
    if e.k == 2 {
        for i in 0..e.n {
            edges.push((
                h.id_at(e.o + i as usize * h.id_size as usize),
                EdgeLabel::Index(i),
            ));
        }
        edges.push((e.c, EdgeLabel::Class));
        return edges;
    }
    // An instance strongly references its Class, which is the route to the loader that defined it.
    edges.push((e.c, EdgeLabel::Class));
    let cx = pre.by_class.get(&e.c);
    let fields = cx.map(|c| c.flat.clone()).unwrap_or_default();
    let skip_referent = cx.map(|c| c.ref_like).unwrap_or(false)
        && !(cfg.final_refs && cx.map(|c| c.final_ref).unwrap_or(false));
    let mut off = e.o;
    for f in fields.iter() {
        if f.ty == 2 {
            let v = h.id_at(off);
            off += h.id_size as usize;
            if v != 0 && !(skip_referent && f.name == "referent") {
                edges.push((v, EdgeLabel::Field(f.name_id)));
            }
        } else {
            off += h.type_size(f.ty) as usize;
        }
    }
    edges
}

/// Expands a batch of nodes, preserving their order, and returns one edge list per node. `OML_DIAG_THREADS`
/// caps the worker count for a loaded or low-core machine.
fn expand_batch(h: &Heap, cfg: &Config, pre: &ExpPre, nodes: &[u64]) -> Vec<Vec<(u64, EdgeLabel)>> {
    let mut n_threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if let Ok(v) = std::env::var("OML_DIAG_THREADS") {
        if let Ok(t) = v.parse::<usize>() {
            if t >= 1 {
                n_threads = n_threads.min(t);
            }
        }
    }
    if nodes.len() < MIN_PARALLEL_BATCH || n_threads <= 1 {
        return nodes.iter().map(|&u| expand_node(h, cfg, u, pre)).collect();
    }
    let chunk = nodes.len().div_ceil(n_threads);
    let per_chunk: Vec<Vec<Vec<(u64, EdgeLabel)>>> = thread::scope(|s| {
        nodes
            .chunks(chunk)
            .map(|ch| {
                s.spawn(move || {
                    ch.iter()
                        .map(|&u| expand_node(h, cfg, u, pre))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|jh| jh.join().unwrap())
            .collect()
    });
    per_chunk.into_iter().flatten().collect()
}

/// Seeds and runs the full BFS. Statics of every class whose loader is not a target — the bootstrap loader
/// included — are roots, and hidden-class statics are optional ones.
pub(crate) fn run_bfs(
    h: &Heap,
    cfg: &Config,
    target_ids: &std::collections::BTreeSet<u64>,
    session_loader_ids: &std::collections::BTreeSet<u64>,
    log: &dyn Fn(&str),
) -> Bfs {
    let pre = ExpPre::build(h);
    let mut state: HashMap<u64, NodeState> = new_map();
    let mut queue: Vec<u64> = Vec::new();

    for &cid in &h.classes_order {
        let meta = &h.classes[&cid];
        let hidden_session = cfg.hidden_session_roots
            && (meta.name.contains("+0x")
                || meta.name.contains("$$Lambda")
                || meta.name.contains("LambdaForm$MH"));
        if meta.loader_id != 0 && session_loader_ids.contains(&meta.loader_id) && !hidden_session {
            continue;
        }
        for &(name_id, value) in &meta.statics {
            if value != 0 {
                let fname = h.strings.get(&name_id).map(|s| &**s).unwrap_or("?");
                let label = format!("STATIC {}.{}", meta.name, fname);
                add_root(value, &label, &mut state, &mut queue);
            }
        }
    }
    for r in &h.roots {
        let label = r.label();
        add_root(r.id, &label, &mut state, &mut queue);
    }
    log(&format!("roots seeded={}", queue.len()));

    let targets_found_0 = if target_ids.is_empty() {
        0
    } else {
        target_ids
            .iter()
            .filter(|&&id| state.get(&id).map(|s| s.dist) == Some(1))
            .count()
    };
    let stop_depth_0 = if !target_ids.is_empty() && targets_found_0 == target_ids.len() {
        target_ids
            .iter()
            .filter_map(|id| state.get(id).map(|s| s.dist))
            .max()
            .unwrap_or(0)
    } else {
        u32::MAX
    };

    let mut bfs = Bfs {
        state,
        queue,
        head: 0,
        target_ids: target_ids.clone(),
        targets_found: targets_found_0,
        stop_depth: stop_depth_0,
    };

    // Wavefront parallelism: take the next slice of the queue (FIFO order), expand it in parallel, then
    // merge in the original order. Expansion depends on no distance state, so the merge order equals the
    // single-threaded visit order.
    let mut t_expand = std::time::Duration::ZERO;
    let mut t_merge = std::time::Duration::ZERO;
    while bfs.head < bfs.queue.len() {
        let end = (bfs.head + BATCH).min(bfs.queue.len());
        let t = std::time::Instant::now();
        let expansions = expand_batch(h, cfg, &pre, &bfs.queue[bfs.head..end]);
        t_expand += t.elapsed();
        let t = std::time::Instant::now();
        let mut stopped = false;
        for (i, edges) in expansions.into_iter().enumerate() {
            let u = bfs.queue[bfs.head + i];
            let du = bfs.state[&u].dist;
            if du >= bfs.stop_depth {
                stopped = true;
                break;
            }
            for (to, label) in edges {
                bfs.visit_edge(h, u, to, label, du);
            }
        }
        t_merge += t.elapsed();
        if stopped {
            // Same semantics as the single-threaded break: the whole BFS ends, not just this batch.
            break;
        }
        bfs.head = end;
    }
    log(&format!(
        "bfs timing expand={:.2}s merge={:.2}s",
        t_expand.as_secs_f64(),
        t_merge.as_secs_f64()
    ));
    log(&format!(
        "bfs visited={} targetsFound={}/{} stopDepth={}",
        bfs.visited(),
        bfs.targets_found,
        target_ids.len(),
        if bfs.stop_depth == u32::MAX {
            "Infinity".to_string()
        } else {
            bfs.stop_depth.to_string()
        }
    ));
    bfs
}

/// step: (is_root, id, label)
pub(crate) fn enumerate_paths(
    h: &Heap,
    bfs: &Bfs,
    target_id: u64,
    limit: usize,
) -> Vec<Vec<(bool, u64, Option<String>)>> {
    let mut paths: Vec<Vec<(bool, u64, Option<String>)>> = Vec::new();
    fn walk(
        h: &Heap,
        bfs: &Bfs,
        id: u64,
        chain: &mut Vec<(bool, u64, Option<String>)>,
        paths: &mut Vec<Vec<(bool, u64, Option<String>)>>,
        limit: usize,
    ) {
        if paths.len() >= limit {
            return;
        }
        if let Some(list) = bfs.state.get(&id) {
            for (p, l) in &list.preds {
                if paths.len() >= limit {
                    return;
                }
                if *p == 0 {
                    let mut path = vec![(true, 0u64, Some(l.text(h)))];
                    path.extend(chain.iter().cloned());
                    paths.push(path);
                } else {
                    chain[0] = (false, id, Some(l.text(h)));
                    let mut next = vec![(false, *p, None)];
                    next.extend(chain.iter().cloned());
                    walk(h, bfs, *p, &mut next, paths, limit);
                }
            }
        }
    }
    walk(
        h,
        bfs,
        target_id,
        &mut vec![(false, target_id, None)],
        &mut paths,
        limit,
    );
    paths
}

pub(crate) fn format_path(h: &Heap, path: &[(bool, u64, Option<String>)]) -> String {
    let mut out = Vec::new();
    for (root, id, label) in path {
        if *root {
            out.push(format!("[{}]", label.clone().unwrap_or_default()));
        } else if label.is_none() {
            out.push(h.object_label(*id));
        } else {
            out.push(format!(
                "--{}--> {}",
                label.clone().unwrap(),
                h.object_label(*id)
            ));
        }
    }
    out.join(" ")
}
