//! HPROF heap-dump analyzer.
//!
//! Module split: `model` (data model), `parse` (HPROF parsing), `bfs` (GC-root BFS and path enumeration),
//! `audit` (the per-category checks). `run` only orchestrates, and the output order is the verified
//! baseline — it is not free to move.
//!
//! Parallelism: the twelve audit sections after the BFS are independent (read-only Heap plus read-only BFS
//! result), so they run on scoped threads, each buffering its own output, and flush in list order — the
//! result is byte-identical to the single-threaded run. The BFS parallelizes its wavefront inside `bfs`.

mod audit;
mod bfs;
pub mod diff;
mod dom;
mod hash;
mod model;
mod parse;
pub mod soft;

use std::io::Write as _;
use std::thread;
use std::time::Instant;

use audit::Ctx;
use bfs::Bfs;
use model::{Root, RootKind};

/// The class loaders a run looks for; `--target` adds to this list.
const SESSION_CLASSES: [&str; 2] = [
    "org/ohmyloader/launcher/SessionClassLoader",
    "org/ohmyloader/core/classloader/OMLClassLoader",
];

/// Predecessors kept per BFS node, which bounds the enumerated paths.
const MAX_PREDS: usize = 5;

pub struct Config {
    pub final_refs: bool,
    pub hidden: bool,
    pub hidden_session_roots: bool,
    pub cp_hook: bool,
    pub threads: bool,
    pub quick: bool,
    pub classvalue: bool,
    /// Retained-size report from the dominator tree, instead of the BFS.
    pub dom: bool,
    /// Length of the top-N list in `--dom` mode.
    pub top: usize,
    pub targets: Vec<String>,
}

/// Shared audit-section signature: read-only context plus the BFS result, writing into a buffer.
type SectionFn = fn(&Ctx, &Bfs, &mut Vec<u8>);

/// Runs the audit sections on scoped threads and flushes their buffers in list order, so the output order
/// does not depend on scheduling.
fn run_parallel(ctx: &Ctx, bfs: &Bfs, sections: &[(&'static str, SectionFn)]) {
    let t0 = std::time::Instant::now();
    let mut bufs: Vec<(usize, Vec<u8>, std::time::Duration)> = thread::scope(|s| {
        let handles: Vec<_> = sections
            .iter()
            .enumerate()
            .map(|(i, (_, f))| {
                s.spawn(move || {
                    let t = std::time::Instant::now();
                    let mut b = Vec::new();
                    f(ctx, bfs, &mut b);
                    (i, b, t.elapsed())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    bufs.sort_by_key(|(i, _, _)| *i);
    for (i, _, d) in &bufs {
        eprintln!("[section] {} {:.2}s", sections[*i].0, d.as_secs_f64());
    }
    let mut stdout = std::io::stdout().lock();
    for (_, b, _) in &bufs {
        let _ = stdout.write_all(b);
    }
    eprintln!("[section] total wall {:.2}s", t0.elapsed().as_secs_f64());
}

pub fn run(path: &str, cfg: &Config) -> Result<(), String> {
    let t0 = Instant::now();
    let log = |m: &str| eprintln!("[{:.2}s] {}", t0.elapsed().as_secs_f64(), m);
    let h = parse::parse(path)?;

    // The dominator tree needs neither the BFS nor the audits: it computes from the parse alone.
    if cfg.dom {
        return dom::report(&h, cfg, cfg.top);
    }

    // root types
    {
        let mut counts: Vec<(&'static str, u32)> = Vec::new();
        for r in &h.roots {
            if let Some(e) = counts.iter_mut().find(|(t, _)| *t == r.kind.name()) {
                e.1 += 1;
            } else {
                counts.push((r.kind.name(), 1));
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1)); // stable, so ties keep first-seen order as the baseline does
        println!(
            "root types: {}",
            counts
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    // targets
    let mut target_names: Vec<&str> = SESSION_CLASSES.to_vec();
    for t in &cfg.targets {
        target_names.push(Box::leak(t.clone().into_boxed_str()));
    }
    let mut session_targets: Vec<(u64, String)> = Vec::new();
    for &id in &h.objects_order {
        let e = &h.objects[&id];
        if e.k != 1 {
            continue;
        }
        let name = h.class_name(e.c);
        if target_names.iter().any(|t| *t == name) {
            session_targets.push((id, name.to_string()));
        }
    }
    log(&format!(
        "targets: {}",
        session_targets
            .iter()
            .map(|(id, n)| format!("{n}@0x{id:x}"))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let target_ids: std::collections::BTreeSet<u64> =
        session_targets.iter().map(|(id, _)| *id).collect();
    let session_loader_ids: std::collections::BTreeSet<u64> = target_ids.clone();

    {
        let direct: Vec<&Root> = h
            .roots
            .iter()
            .filter(|r| r.kind == RootKind::JniGlobal && target_ids.contains(&r.id))
            .collect();
        println!("direct JNI roots to session loaders={}", direct.len());
        for r in direct {
            println!(
                "  JNI_GLOBAL target=0x{:x} jni_global_ref_id=0x{:x}",
                r.id, r.jni_ref
            );
        }
    }

    let ctx = Ctx {
        h,
        session_targets,
        target_ids,
        session_loader_ids,
        t0,
    };

    if cfg.hidden {
        audit::hidden_special(&ctx);
        ctx.log("done");
        return Ok(());
    }

    let bfs = bfs::run_bfs(
        &ctx.h,
        cfg,
        &ctx.target_ids,
        &ctx.session_loader_ids,
        &|m| ctx.log(m),
    );

    {
        let unknown: Vec<&Root> = ctx
            .h
            .roots
            .iter()
            .filter(|r| !ctx.h.classes.contains_key(&r.id) && !ctx.h.objects.contains_key(&r.id))
            .collect();
        if unknown.is_empty() {
            println!("unknown root targets=0");
        } else {
            println!("unknown root targets={}", unknown.len());
            for r in unknown.iter().take(40) {
                println!("  {} 0x{:x}", r.kind.name(), r.id);
            }
        }
    }

    if cfg.cp_hook {
        audit::cp_hook(&ctx);
    }

    if cfg.threads {
        audit::threads(&ctx);
    }

    for (tid, tname) in &ctx.session_targets {
        let d = bfs.dist_of(tid);
        let inner = if d.is_none() {
            "no strong root path"
        } else {
            ""
        };
        println!(
            "\n=== target {tname}@0x{tid:x} dist={} ({inner})",
            d.map(|v| v.to_string())
                .unwrap_or_else(|| "unreachable".into())
        );
        let Some(_d) = d else { continue };
        let mut paths = bfs::enumerate_paths(&ctx.h, &bfs, *tid, 5);
        paths.sort_by_key(|p| p.len()); // stable, so equal lengths keep enumeration order
        for (i, p) in paths.iter().enumerate() {
            println!(
                "  #{} len={}\n      {}",
                i + 1,
                p.len(),
                bfs::format_path(&ctx.h, p)
            );
        }
    }

    if cfg.quick {
        log("quick done");
        return Ok(());
    }

    const GROUP_A: [(&str, SectionFn); 8] = [
        ("jni_global_methodtypes", audit::jni_global_methodtypes),
        ("session_references", audit::session_references),
        (
            "persistent_invoke_foreign",
            audit::persistent_invoke_foreign,
        ),
        ("native_libraries", audit::native_libraries),
        ("lwjgl_upcalls", audit::lwjgl_upcalls),
        ("console_statics", audit::console_statics),
        ("classvalue_entries", audit::classvalue_entries),
        (
            "classvalue_field_deep_audit",
            audit::classvalue_field_deep_audit,
        ),
    ];
    run_parallel(&ctx, &bfs, &GROUP_A);

    if cfg.classvalue {
        log("classvalue done");
        return Ok(());
    }

    const GROUP_B: [(&str, SectionFn); 4] = [
        ("reflection_data_owners", audit::reflection_data_owners),
        ("jna_statics", audit::jna_statics),
        ("lambdaform_reverse_trace", audit::lambdaform_reverse_trace),
        ("shutdown_hooks", audit::shutdown_hooks),
    ];
    run_parallel(&ctx, &bfs, &GROUP_B);

    log("done");
    Ok(())
}
