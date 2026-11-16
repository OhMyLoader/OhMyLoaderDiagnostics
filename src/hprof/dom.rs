//! Dominator tree (Lengauer-Tarjan semi-NCA) and retained size.
//!
//! The graph is the same strong-reference graph the BFS expands (`expand_node` edges), but the roots are
//! the full GC-reachability seeding: every class static plus every VM root, where the BFS seeds from
//! outside that set. Raw arrays such as `byte[]` are leaf nodes whose bytes count toward their holder.
//!
//! Steps: number the nodes → two-pass CSR (succ/pred, edges filtered to known nodes) → DFS from the virtual
//! root (dfn/parent/RPO) → LT for the idomators (semi + bucket + union-find with path compression) →
//! accumulate retained bottom-up in reverse dfn order. CHK iteration is not used because it degrades on this
//! graph's long dominator chains (one pass over 50s); LT's eval/link path compression converges in about 1s.
//!
//! Everything after numbering is indexed by dfn (1..R, 0 = virtual root); `vertex` maps back through RPO.

use super::Config;
use super::bfs::{ExpPre, expand_node};
use super::diff::fmt_bytes;
use super::hash::{HashMap, new_map};
use super::model::Heap;
use std::time::Instant;

/// LT eval: the dfn on the path from `x` (inclusive) up to its forest root with the smallest `semi`, with
/// path compression.
fn eval(x: usize, anc: &mut [u32], best: &mut [u32], semi: &[u32]) -> usize {
    if anc[x] == u32::MAX {
        return x;
    }
    // Collect the path x → forest root: path[0] = x, and path.last()'s parent is that root.
    let mut path = Vec::new();
    let mut y = x;
    while anc[y] != u32::MAX {
        path.push(y);
        y = anc[y] as usize;
    }
    let root = y;
    // Propagate best downward from the root to x, re-pointing every node on the path at the root.
    for j in (0..path.len()).rev() {
        let c = path[j];
        let p = if j + 1 < path.len() {
            path[j + 1]
        } else {
            root
        };
        if semi[best[p] as usize] < semi[best[c] as usize] {
            best[c] = best[p];
        }
        anc[c] = root as u32;
    }
    best[x] as usize
}

pub(crate) fn report(h: &Heap, cfg: &Config, top: usize) -> Result<(), String> {
    let t0 = Instant::now();
    let log = |m: &str| eprintln!("[{:.2}s] {}", t0.elapsed().as_secs_f64(), m);
    let id_size = h.id_size as usize;

    // ---- 1. Node table: instances and object arrays, then classes, then raw arrays (disjoint id spaces)
    let n_obj = h.objects_order.len();
    let n_cls = h.classes_order.len();
    let n_prim = h.prim_arrays.len();
    let n = n_obj + n_cls + n_prim;
    let mut ids: Vec<u64> = Vec::with_capacity(n);
    let mut kinds: Vec<u8> = Vec::with_capacity(n); // 0 inst, 1 objarr, 2 prim, 3 class
    for &id in &h.objects_order {
        ids.push(id);
        kinds.push(if h.objects[&id].k == 1 { 0 } else { 1 });
    }
    ids.extend(h.classes_order.iter().copied());
    kinds.extend(std::iter::repeat(3).take(n_cls));
    ids.extend(h.prim_arrays.keys().copied());
    kinds.extend(std::iter::repeat(2).take(n_prim));
    let mut idx: HashMap<u64, u32> = new_map();
    idx.reserve(n);
    for (i, &id) in ids.iter().enumerate() {
        idx.insert(id, i as u32);
    }
    log(&format!(
        "nodes={} (inst+arr={} class={} prim={})",
        n, n_obj, n_cls, n_prim
    ));

    let shallow: Vec<u64> = (0..n)
        .map(|i| match kinds[i] {
            0 => h.objects[&ids[i]].n as u64,
            1 => h.objects[&ids[i]].n as u64 * id_size as u64,
            2 => {
                let &(ty, c) = h.prim_arrays.get(&ids[i]).unwrap();
                c * h.type_size(ty) as u64
            }
            _ => 0,
        })
        .collect();

    // ---- 2. Root seeding: every class static plus every VM root, i.e. full GC reachability
    let mut seeds: Vec<u32> = Vec::new();
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    for &cid in &h.classes_order {
        for &(_, value) in &h.classes[&cid].statics {
            if value != 0 && seen.insert(value) {
                if let Some(&v) = idx.get(&value) {
                    seeds.push(v);
                }
            }
        }
    }
    for r in &h.roots {
        if r.id != 0 && seen.insert(r.id) {
            if let Some(&v) = idx.get(&r.id) {
                seeds.push(v);
            }
        }
    }
    log(&format!("seeds={}", seeds.len()));

    let pre = ExpPre::build(h);

    // ---- 3. Two-pass CSR: count, then fill (self-loops dropped; each seed gets one virtual-root pred)
    let mut succ_cnt = vec![0u32; n];
    let mut pred_cnt = vec![0u32; n];
    {
        for i in 0..n {
            for (to, _l) in expand_node(h, cfg, ids[i], &pre) {
                if let Some(&v) = idx.get(&to) {
                    if v as usize != i {
                        succ_cnt[i] += 1;
                        pred_cnt[v as usize] += 1;
                    }
                }
            }
        }
        for &s in &seeds {
            pred_cnt[s as usize] += 1; // the edge from the virtual root R = n
        }
    }
    let mut soff = Vec::<u64>::with_capacity(n + 1);
    let mut poff = Vec::<u64>::with_capacity(n + 1);
    let (mut s, mut p) = (0u64, 0u64);
    for i in 0..n {
        soff.push(s);
        poff.push(p);
        s += succ_cnt[i] as u64;
        p += pred_cnt[i] as u64;
    }
    soff.push(s);
    poff.push(p);
    let total_e = s;
    drop(succ_cnt);
    drop(pred_cnt);
    log(&format!(
        "edges={} csr+preds={:.0}MB",
        total_e,
        (total_e * 8 + p * 8 + n as u64 * 16) as f64 / 1048576.0
    ));

    let mut succ = vec![0u32; total_e as usize];
    let mut pred = vec![0u32; p as usize];
    {
        let mut sc = soff[..n].to_vec();
        let mut pc = poff[..n].to_vec();
        for i in 0..n {
            for (to, _l) in expand_node(h, cfg, ids[i], &pre) {
                if let Some(&v) = idx.get(&to) {
                    if v as usize != i {
                        succ[sc[i] as usize] = v;
                        sc[i] += 1;
                        pred[pc[v as usize] as usize] = i as u32;
                        pc[v as usize] += 1;
                    }
                }
            }
        }
        for &sd in &seeds {
            pred[pc[sd as usize] as usize] = n as u32; // the virtual root
        }
    }
    log("edges built");

    // ---- 4. DFS from the virtual root R = n: dfn / parent / RPO, all in dfn index space
    let r = n as u32;
    let mut dfn = vec![u32::MAX; n + 1];
    let mut rpo: Vec<u32> = Vec::new();
    let mut parent_dfn: Vec<u32> = Vec::new(); // parallel to rpo: the DFS parent's dfn
    dfn[r as usize] = 0;
    rpo.push(r);
    parent_dfn.push(0);
    let mut stack: Vec<(u32, usize, u32)> = vec![(r, 0, 0)]; // (node, edge cursor, DFS parent dfn)
    while let Some(top) = stack.last_mut() {
        let (u, cur, pdfn) = *top;
        let next = if u == r {
            if cur < seeds.len() {
                seeds[cur]
            } else {
                u32::MAX
            }
        } else {
            let (b, e) = (soff[u as usize] as usize, soff[u as usize + 1] as usize);
            if cur < e - b { succ[b + cur] } else { u32::MAX }
        };
        if next != u32::MAX {
            top.1 += 1;
            if dfn[next as usize] == u32::MAX {
                dfn[next as usize] = rpo.len() as u32;
                rpo.push(next);
                parent_dfn.push(pdfn);
                stack.push((next, 0, dfn[next as usize]));
            }
        } else {
            stack.pop();
        }
    }
    let rc = rpo.len();
    let reach_shallow: u64 = rpo[1..].iter().map(|&v| shallow[v as usize]).sum();
    log(&format!(
        "reachable={}/{} shallow={} dfs done",
        rc - 1,
        n,
        fmt_bytes(reach_shallow)
    ));

    // ---- 5. LT semi-NCA, indexed by dfn (0 = root)
    let mut semi: Vec<u32> = (0..rc as u32).collect(); // semi[i] = i to start
    let mut ancestor = vec![u32::MAX; rc];
    let mut best: Vec<u32> = (0..rc as u32).collect();
    let mut bhead = vec![u32::MAX; rc]; // head of the bucket[semi dfn] linked list
    let mut bnext = vec![u32::MAX; rc];
    let mut idom = vec![u32::MAX; rc];
    idom[0] = 0;
    for i in (1..rc).rev() {
        let wg = rpo[i] as usize;
        // step 2: semi[w] = min over preds of semi[eval(pred)]
        let mut si = i as u32;
        for &p in &pred[poff[wg] as usize..poff[wg + 1] as usize] {
            let pd = dfn[p as usize];
            if pd == u32::MAX {
                continue; // an in-edge from a node the DFS never reached
            }
            let u = eval(pd as usize, &mut ancestor, &mut best, &semi);
            if semi[u] < si {
                si = semi[u];
            }
        }
        semi[i] = si;
        // bucket[si] ← i
        bnext[i] = bhead[si as usize];
        bhead[si as usize] = i as u32;
        // link(parent[i], i)
        let par = parent_dfn[i] as usize;
        ancestor[i] = par as u32;
        // step 3: drain bucket[parent[i]]
        let mut w2 = bhead[par];
        while w2 != u32::MAX {
            let w2n = w2 as usize;
            let nxt = bnext[w2n];
            let u = eval(w2n, &mut ancestor, &mut best, &semi);
            if semi[u] == semi[w2n] {
                idom[w2n] = par as u32;
            } else {
                idom[w2n] = u as u32; // provisional; step 4 corrects it
            }
            w2 = nxt;
        }
        bhead[par] = u32::MAX;
    }
    // step 4: resolve the provisional idoms
    for i in 1..rc {
        if idom[i] != semi[i] {
            idom[i] = idom[idom[i] as usize];
        }
    }
    log("lt done");

    // ---- 6. Accumulate retained bottom-up; an idom always has a smaller dfn, so reverse dfn order is safe.
    // Slot n is the virtual root, whose retained size is the total shallow size of everything reachable.
    let mut ret = vec![0u64; n + 1];
    let mut cnt = vec![0u32; n + 1];
    for i in 1..rc {
        let v = rpo[i] as usize;
        ret[v] = shallow[v];
        cnt[v] = 1;
    }
    for i in (1..rc).rev() {
        let v = rpo[i] as usize;
        let p = rpo[idom[i] as usize] as usize;
        ret[p] += ret[v];
        cnt[p] += cnt[v];
    }

    // ---- 7. Report
    let total_shallow: u64 = shallow.iter().sum();
    println!(
        "dominator tree: nodes={} reachable={} edges={} unreachable_bytes={}",
        n,
        rc - 1,
        total_e,
        fmt_bytes(total_shallow - reach_shallow)
    );
    let mut top_list: Vec<u32> = rpo[1..].to_vec();
    top_list.sort_by(|&a, &b| {
        ret[b as usize].cmp(&ret[a as usize]).then_with(|| {
            node_label(h, &ids, &kinds, a as usize).cmp(&node_label(h, &ids, &kinds, b as usize))
        })
    });
    for (i, &v) in top_list.iter().take(top).enumerate() {
        let vi = v as usize;
        println!(
            "  #{} retained={} shallow={} dominated={}  {}",
            i + 1,
            fmt_bytes(ret[vi]),
            fmt_bytes(shallow[vi]),
            cnt[vi],
            node_label(h, &ids, &kinds, vi)
        );
    }
    Ok(())
}

fn node_label(h: &Heap, ids: &[u64], kinds: &[u8], i: usize) -> String {
    match kinds[i] {
        3 => format!("class {}", h.class_name(ids[i])),
        2 => {
            let &(ty, c) = h.prim_arrays.get(&ids[i]).unwrap();
            let name = match ty {
                4 => "boolean",
                5 => "char",
                6 => "float",
                7 => "double",
                8 => "byte",
                9 => "short",
                10 => "int",
                11 => "long",
                _ => "?",
            };
            format!("{name}[{c}]")
        }
        _ => h.object_label(ids[i]),
    }
}
