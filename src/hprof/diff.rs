//! hprof-diff: compare two heap dumps.
//!
//! The two dumps are aligned by class name, because object ids do not mean anything across dumps. Instance
//! counts, object arrays by element class, and raw-array counts and bytes are reported as deltas ranked by
//! |delta|. The intended use is a soft-restart leak: dump before and after the restart and read what
//! survived.

use super::parse;
use std::time::Instant;

struct Delta {
    name: String,
    old: u64,
    new: u64,
}

impl Delta {
    fn diff(&self) -> i64 {
        self.new as i64 - self.old as i64
    }
}

fn count_per_class(h: &super::model::Heap, kind: u8) -> std::collections::HashMap<String, u64> {
    // Plain std HashMap: string keys are not the hot path, and the output order comes from the sorted name
    // list in `print_deltas`, not from this map.
    let mut m: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for &id in &h.objects_order {
        let e = &h.objects[&id];
        if e.k == kind {
            *m.entry(h.class_name(e.c).to_string()).or_insert(0) += 1;
        }
    }
    m
}

pub(crate) fn fmt_bytes(v: u64) -> String {
    if v >= 1 << 30 {
        format!("{:.2}G", v as f64 / (1 << 30) as f64)
    } else if v >= 1 << 20 {
        format!("{:.1}M", v as f64 / (1 << 20) as f64)
    } else if v >= 1 << 10 {
        format!("{:.1}K", v as f64 / (1 << 10) as f64)
    } else {
        format!("{v}B")
    }
}

fn print_deltas(
    title: &str,
    old: &std::collections::HashMap<String, u64>,
    new: &std::collections::HashMap<String, u64>,
    top: usize,
) {
    let mut deltas: Vec<Delta> = Vec::new();
    let mut names: Vec<&String> = old.keys().chain(new.keys()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let o = old.get(name).copied().unwrap_or(0);
        let n = new.get(name).copied().unwrap_or(0);
        if o != n {
            deltas.push(Delta {
                name: name.clone(),
                old: o,
                new: n,
            });
        }
    }
    deltas.sort_by(|a, b| {
        b.diff()
            .abs()
            .cmp(&a.diff().abs())
            .then(a.name.cmp(&b.name))
    });
    println!("{title} changed={} (top {top} by |delta|)", deltas.len());
    let width = deltas
        .iter()
        .map(|d| d.old.max(d.new))
        .max()
        .map(|v| v.to_string().len())
        .unwrap_or(5);
    for d in deltas.iter().take(top) {
        let sign = if d.diff() > 0 { "+" } else { "" };
        println!(
            "  {sign}{:>6} {:name$} -> {:name$}  {}",
            d.diff(),
            d.old,
            d.new,
            d.name,
            name = width
        );
    }
}

pub fn run(old_path: &str, new_path: &str, top: usize) -> Result<(), String> {
    let t0 = Instant::now();
    let h0 = parse::parse(old_path)?;
    let h1 = parse::parse(new_path)?;
    eprintln!("[{:.2}s] both parsed", t0.elapsed().as_secs_f64());

    let old_sz = std::fs::metadata(old_path).map(|m| m.len()).unwrap_or(0);
    let new_sz = std::fs::metadata(new_path).map(|m| m.len()).unwrap_or(0);
    println!(
        "old: {} ({})  objects={} classes={}",
        old_path,
        fmt_bytes(old_sz),
        h0.objects.len(),
        h0.classes.len()
    );
    println!(
        "new: {} ({})  objects={} classes={}",
        new_path,
        fmt_bytes(new_sz),
        h1.objects.len(),
        h1.classes.len()
    );
    println!(
        "instances: {} -> {} ({:+})",
        h0.objects_order.len(),
        h1.objects_order.len(),
        h1.objects_order.len() as i64 - h0.objects_order.len() as i64
    );

    // Instance count per class name.
    let inst0 = count_per_class(&h0, 1);
    let inst1 = count_per_class(&h1, 1);
    println!();
    print_deltas("instances by class:", &inst0, &inst1, top);

    // Object arrays per element class.
    let arr0 = count_per_class(&h0, 2);
    let arr1 = count_per_class(&h1, 2);
    println!();
    print_deltas("object arrays by element class:", &arr0, &arr1, top);

    // byte[] and the other raw arrays.
    let b0 = h0.byte_arrays.len() as u64;
    let b1 = h1.byte_arrays.len() as u64;
    let bb0: u64 = h0.byte_arrays.values().map(|&(_, n)| n as u64).sum();
    let bb1: u64 = h1.byte_arrays.values().map(|&(_, n)| n as u64).sum();
    println!();
    println!(
        "byte[]: {} -> {} ({:+})  {} -> {} ({:+})",
        b0,
        b1,
        b1 as i64 - b0 as i64,
        fmt_bytes(bb0),
        fmt_bytes(bb1),
        bb1 as i64 - bb0 as i64
    );
    let p0: u64 = h0.prim_arrays.len() as u64;
    let p1: u64 = h1.prim_arrays.len() as u64;
    let prim_bytes = |h: &super::model::Heap| -> u64 {
        h.prim_arrays
            .values()
            .map(|&(ty, c)| c * h.type_size(ty) as u64)
            .sum()
    };
    let pb0 = prim_bytes(&h0);
    let pb1 = prim_bytes(&h1);
    println!(
        "prim arrays: {} -> {} ({:+})  {} -> {} ({:+})",
        p0,
        p1,
        p1 as i64 - p0 as i64,
        fmt_bytes(pb0),
        fmt_bytes(pb1),
        pb1 as i64 - pb0 as i64
    );
    Ok(())
}
