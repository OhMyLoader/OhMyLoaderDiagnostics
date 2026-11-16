//! Audit sections: the targeted checks that run after the BFS (JNI, Reference, ClassValue, JNA,
//! hidden classes, shutdown hooks).
//!
//! Sections run in the order `run()` lists them, and that output order is the historically verified
//! baseline — including where the orphaned "persistent JNA statics" header lands.

use super::hash::{HashMap, new_map};
use std::io::Write as _;
use std::rc::Rc;
use std::time::Instant;

use super::bfs::Bfs;
use super::model::{FField, Heap, Obj, RootKind, json_string};

/// Read-only state shared by the audit sections; it crosses threads, so it has to be `Sync`.
pub(crate) struct Ctx {
    pub(crate) h: Heap,
    pub(crate) session_targets: Vec<(u64, String)>,
    pub(crate) target_ids: std::collections::BTreeSet<u64>,
    pub(crate) session_loader_ids: std::collections::BTreeSet<u64>,
    pub(crate) t0: Instant,
}

impl Ctx {
    pub(crate) fn log(&self, m: &str) {
        eprintln!("[{:.2}s] {}", self.t0.elapsed().as_secs_f64(), m);
    }
}

// ---- --hidden: hidden-class specialist, runs before the BFS and exits on its own ----

pub(crate) fn hidden_special(ctx: &Ctx) {
    let h = &ctx.h;
    let session_loader_ids = &ctx.session_loader_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut found = 0;
    for &cid in &h.classes_order {
        let meta = &h.classes[&cid];
        if !meta.name.starts_with("java/lang/invoke/LambdaForm$MH") {
            continue;
        }
        for &(name_id, value) in &meta.statics {
            if value == 0 {
                continue;
            }
            let Some(value_e) = h.objects.get(&value) else {
                continue;
            };
            if value_e.k != 1
                || h.class_name(value_e.c) != "java/lang/invoke/DirectMethodHandle$StaticAccessor"
            {
                continue;
            }
            let field_type = h.instance_object_field_with(ff_cache, value_e, "fieldType");
            let static_base = h.instance_object_field_with(ff_cache, value_e, "staticBase");
            let ft_loader = field_type
                .and_then(|f| h.classes.get(&f))
                .map(|m| m.loader_id);
            let sb_loader = static_base
                .and_then(|s| h.classes.get(&s))
                .map(|m| m.loader_id);
            if ft_loader
                .map(|l| session_loader_ids.contains(&l))
                .unwrap_or(false)
                || sb_loader
                    .map(|l| session_loader_ids.contains(&l))
                    .unwrap_or(false)
            {
                found += 1;
                let f = h.class_name(field_type.unwrap_or(0));
                let s = h.class_name(static_base.unwrap_or(0));
                println!(
                    "  hidden mirror=0x{cid:x} klass-name={}.{cls} value=0x{value:x} fieldType={f} staticBase={s}",
                    meta.name,
                    cls = h.strings.get(&name_id).map(|s| &**s).unwrap_or("?")
                );
            }
        }
    }
    for &cid in &h.classes_order {
        let name = h.class_name(cid).to_string();
        if name == "org/ohmyloader/adapter/common/MinecraftContentRegistry" {
            for &(name_id, value) in &h.classes[&cid].statics {
                if h.strings.get(&name_id).map(|s| &**s) == Some("registryAccessor") {
                    let label = if value != 0 {
                        h.object_label(value)
                    } else {
                        "null".into()
                    };
                    println!("  MinecraftContentRegistry.registryAccessor -> {label}");
                }
            }
        }
        if name == "org/ohmyloader/adapter/v26_3/V26_3RegistryAccessor" {
            println!("  V26_3RegistryAccessor class is loaded");
        }
    }
    for &cid in &h.classes_order {
        let meta = &h.classes[&cid];
        if !meta.name.starts_with("jdk/proxy2/$Proxy") {
            continue;
        }
        let mut refs: Vec<String> = Vec::new();
        for &r in &meta.cp_refs {
            if h.classes.contains_key(&r) {
                refs.push(format!("class {}", h.class_name(r)));
            } else if let Some(e) = h.objects.get(&r) {
                if h.class_name(e.c) == "java/lang/String" {
                    if let Some(text) = h.decoded_string(r) {
                        if !text.is_empty() {
                            refs.push(format!("str {text}"));
                        }
                    }
                }
            }
        }
        refs.dedup();
        let uniq: Vec<String> = {
            let mut seen = std::collections::BTreeSet::new();
            refs.retain(|s| seen.insert(s.clone()));
            refs
        };
        println!(
            "  {} refs: {}",
            meta.name,
            uniq.into_iter().take(20).collect::<Vec<_>>().join(", ")
        );
    }
    println!("  hidden candidates={found}");
}

// ---- --cp-hook ----

pub(crate) fn cp_hook(ctx: &Ctx) {
    let h = &ctx.h;
    let hook_ids: std::collections::BTreeSet<u64> = h
        .classes_order
        .iter()
        .filter(|&&id| {
            let n = h.class_name(id);
            matches!(
                n,
                "org/ohmyloader/api/hook/HookValue"
                    | "org/ohmyloader/api/hook/HookContext"
                    | "org/ohmyloader/core/OMLCore"
                    | "org/ohmyloader/core/classloader/OMLClassLoader"
                    | "org/ohmyloader/launcher/SessionClassLoader"
            )
        })
        .copied()
        .collect();
    for &id in &h.classes_order {
        let meta = &h.classes[&id];
        let mut seen = std::collections::BTreeSet::new();
        let refs: Vec<u64> = meta
            .cp_refs
            .iter()
            .filter(|r| hook_ids.contains(r) && seen.insert(**r))
            .copied()
            .collect();
        if !refs.is_empty() {
            let names: Vec<&str> = refs.iter().map(|&r| h.class_name(r)).collect();
            println!("cp-ref {} -> {}", meta.name, names.join(","));
        }
    }
}

// ---- --threads ----

pub(crate) fn threads(ctx: &Ctx) {
    let h = &ctx.h;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut threads: Vec<(u32, u64)> = Vec::new();
    for r in &h.roots {
        if r.kind == RootKind::ThreadObject {
            if let Some(e) = threads.iter_mut().find(|(s, _)| *s == r.thread) {
                e.1 = r.id;
            } else {
                threads.push((r.thread, r.id));
            }
        }
    }
    threads.sort_by_key(|(s, _)| *s);
    for (serial, id) in threads {
        let Some(e) = h.objects.get(&id) else {
            continue;
        };
        if e.k != 1 {
            continue;
        }
        let name = h
            .instance_object_field_with(ff_cache, e, "name")
            .and_then(|v| h.decoded_string(v))
            .unwrap_or_else(|| "null".into());
        let shown = if name == "null" {
            "null".to_string()
        } else {
            json_string(&name)
        };
        println!(
            "thread serial={serial} name={shown} class={}",
            h.class_name(e.c)
        );
    }
}

// ---- JNI Global MethodTypes ----

pub(crate) fn jni_global_methodtypes(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    writeln!(out, "\n=== JNI Global MethodTypes with non-bootstrap types").unwrap();
    let mut mt_total = 0u32;
    let mut mt_bad = 0u32;
    let mut seen = std::collections::BTreeSet::new();
    for &id in &h.jni_globals {
        if !seen.insert(id) {
            continue;
        }
        let Some(entry) = h.objects.get(&id).copied() else {
            continue;
        };
        if entry.k != 1 || h.class_name(entry.c) != "java/lang/invoke/MethodType" {
            continue;
        }
        mt_total += 1;
        let rtype = h.instance_object_field_with(ff_cache, &entry, "rtype");
        let ptypes = h.instance_object_field_with(ff_cache, &entry, "ptypes");
        let mut type_ids: Vec<u64> = Vec::new();
        if let Some(pt) = ptypes {
            if let Some(arr) = h.objects.get(&pt) {
                if arr.k == 2 {
                    for i in 0..arr.n {
                        type_ids.push(h.id_at(arr.o + i as usize * h.id_size as usize));
                    }
                }
            }
        }
        if let Some(rt) = rtype {
            type_ids.push(rt);
        }
        let mut non_bootstrap = Vec::new();
        for &tid in &type_ids {
            let Some(meta) = h.classes.get(&tid) else {
                continue;
            };
            if meta.loader_id == 0 {
                continue;
            }
            let loader_name = h
                .objects
                .get(&meta.loader_id)
                .map(|lo| h.class_name(lo.c).to_string())
                .unwrap_or_else(|| format!("<loader:0x{:x}>", meta.loader_id));
            non_bootstrap.push(format!("{} (loader={})", h.class_name(tid), loader_name));
        }
        if !non_bootstrap.is_empty() {
            mt_bad += 1;
            let sig: Vec<&str> = type_ids.iter().map(|&t| h.class_name(t)).collect();
            writeln!(out, "  0x{id:x} ({})", sig.join(",")).unwrap();
            for l in non_bootstrap {
                writeln!(out, "      {l}").unwrap();
            }
        }
    }
    writeln!(out, "  methodTypes={mt_total} withNonBootstrap={mt_bad}").unwrap();
}

// ---- Reference objects whose referent belongs to the session ----

pub(crate) fn session_references(ctx: &Ctx, bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut ref_cache_own = new_map();
    let ref_cache = &mut ref_cache_own;
    let mut final_cache_own = new_map();
    let final_cache = &mut final_cache_own;
    writeln!(
        out,
        "\n=== Reference objects whose referent belongs to the session"
    )
    .unwrap();
    let ref_class_ids: std::collections::BTreeSet<u64> = h
        .classes_order
        .iter()
        .filter(|&&cid| h.is_reference_like(ref_cache, cid))
        .copied()
        .collect();
    for &cid in &ref_class_ids {
        if h.class_name(cid).contains("Finalizer") {
            let mut chain = Vec::new();
            let mut c = cid;
            while c != 0 {
                chain.push(h.class_name(c).to_string());
                c = h.classes.get(&c).map(|m| m.super_id).unwrap_or(0);
            }
            writeln!(
                out,
                "  [debug] {} isFinalReference={} chain={}",
                h.class_name(cid),
                h.is_final_reference(final_cache, cid),
                chain.join(" <- ")
            )
            .unwrap();
        }
    }
    let session_ref = |v: u64| -> Option<String> {
        if target_ids.contains(&v) {
            return Some(format!("loader {}", h.object_label(v)));
        }
        if let Some(meta) = h.classes.get(&v) {
            if target_ids.contains(&meta.loader_id) {
                return Some(format!("class {}", meta.name));
            }
        }
        if let Some(ve) = h.objects.get(&v) {
            if ve.k == 1 {
                if let Some(vm) = h.classes.get(&ve.c) {
                    if target_ids.contains(&vm.loader_id) {
                        return Some(format!("instance {}", vm.name));
                    }
                }
            }
        }
        None
    };
    let mut refs = 0u32;
    let mut seen_types: Vec<(String, (u32, u32))> = Vec::new();
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 || !ref_class_ids.contains(&e.c) {
            continue;
        }
        let Some(referent) = h.instance_object_field_with(ff_cache, &e, "referent") else {
            continue;
        };
        if referent == 0 {
            continue;
        }
        let Some(what) = session_ref(referent) else {
            continue;
        };
        let ty = h.class_name(e.c).to_string();
        let counts = match seen_types.iter_mut().find(|(t, _)| *t == ty) {
            Some((_, c)) => c,
            None => {
                seen_types.push((ty.clone(), (0, 0)));
                &mut seen_types.last_mut().unwrap().1
            }
        };
        counts.0 += 1;
        if bfs.reachable(&id) {
            counts.1 += 1;
        }
        refs += 1;
        if bfs.reachable(&id) || refs <= 40 {
            writeln!(
                out,
                "  {ty}@0x{id:x} reachable={} dist={} referent=0x{referent:x} -> {what}",
                bfs.reachable(&id),
                bfs.dist_of(&id)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "-".into())
            )
            .unwrap();
        }
    }
    for (ty, (n, reachable)) in &seen_types {
        writeln!(out, "  {ty}: total={n} reachable={reachable}").unwrap();
    }
    if refs == 0 {
        writeln!(out, "  none").unwrap();
    }
}

// ---- persistent invoke/foreign/lwjgl/jna objects ----

pub(crate) fn persistent_invoke_foreign(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut cache2_own = new_map();
    let cache2 = &mut cache2_own;
    let mut ref_cache_own = new_map();
    let ref_cache = &mut ref_cache_own;
    writeln!(
        out,
        "\n=== persistent invoke/foreign/lwjgl/jna objects with session references"
    )
    .unwrap();
    const PREFIXES: [&str; 4] = [
        "jdk/internal/foreign",
        "java/lang/invoke",
        "org/lwjgl",
        "com/sun/jna",
    ];
    let mut hits = 0u32;
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 {
            continue;
        }
        let name = h.class_name(e.c);
        if !PREFIXES.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        if let Some(meta) = h.classes.get(&e.c) {
            if target_ids.contains(&meta.loader_id) {
                continue;
            }
        }
        let fields = h.flattened_fields(cache2, e.c);
        let skip_referent = h.is_reference_like(ref_cache, e.c);
        let mut off = e.o;
        let mut refs = Vec::new();
        for f in fields.iter() {
            if f.ty == 2 {
                let v = h.id_at(off);
                off += h.id_size as usize;
                if v == 0 || (skip_referent && f.name == "referent") {
                    continue;
                }
                if target_ids.contains(&v) {
                    refs.push(format!("{} -> {}", f.name, h.object_label(v)));
                    continue;
                }
                if let Some(m) = h.classes.get(&v) {
                    if target_ids.contains(&m.loader_id) {
                        refs.push(format!("{} -> class {}", f.name, m.name));
                    }
                } else if let Some(ve) = h.objects.get(&v) {
                    if let Some(vm) = h.classes.get(&ve.c) {
                        if target_ids.contains(&vm.loader_id) {
                            refs.push(format!("{} -> {}@0x{:x}", f.name, vm.name, v));
                        }
                    }
                }
            } else {
                off += h.type_size(f.ty) as usize;
            }
        }
        if !refs.is_empty() {
            hits += 1;
            if hits <= 60 {
                writeln!(out, "  {}@0x{id:x}: {}", name, refs.join(", ")).unwrap();
            }
        }
    }
    writeln!(out, "  total objects={hits}").unwrap();
}

// ---- NativeLibraries association ----

pub(crate) fn native_libraries(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let session_targets = &ctx.session_targets;
    writeln!(out, "\n=== session loaders: NativeLibraries association").unwrap();
    for (tid, tname) in session_targets {
        let Some(e) = h.objects.get(tid).copied() else {
            continue;
        };
        if e.k != 1 {
            continue;
        }
        let libs_id = h.instance_field(&e, "libraries").map(|v| v.1).unwrap_or(0);
        writeln!(
            out,
            "  {tname}@0x{tid:x} libraries={}",
            if libs_id != 0 {
                format!("0x{libs_id:x}")
            } else {
                "null".into()
            }
        )
        .unwrap();
        let Some(libs) = (if libs_id != 0 {
            h.objects.get(&libs_id).copied()
        } else {
            None
        }) else {
            continue;
        };
        let map_id = h
            .instance_field(&libs, "libraries")
            .map(|v| v.1)
            .unwrap_or(0);
        let map = if map_id != 0 {
            h.objects.get(&map_id).copied()
        } else {
            None
        };
        let back = h.instance_field(&libs, "loader").map(|v| v.1).unwrap_or(0);
        let caller = h.instance_field(&libs, "caller").map(|v| v.1).unwrap_or(0);
        let size = map
            .as_ref()
            .and_then(|m| h.instance_field(m, "size"))
            .map(|v| v.1);
        let table_id = map
            .as_ref()
            .and_then(|m| h.instance_object_field(m, "table"));
        let table = table_id.and_then(|t| h.objects.get(&t).copied());
        let base_count = map
            .as_ref()
            .and_then(|m| h.instance_field(m, "baseCount"))
            .map(|v| v.1);
        writeln!(
            out,
            "      map={} class={} size={} tableId={} tableLen={} baseCount={}",
            if map_id != 0 {
                format!("0x{map_id:x}")
            } else {
                "null".into()
            },
            map.as_ref().map(|m| h.class_name(m.c)).unwrap_or("-"),
            size.map(|v| v.to_string())
                .unwrap_or_else(|| "undefined".into()),
            table_id
                .filter(|&t| t != 0)
                .map(|t| format!("0x{t:x}"))
                .unwrap_or_else(|| "null".into()),
            table
                .as_ref()
                .filter(|t| t.k == 2)
                .map(|t| t.n.to_string())
                .unwrap_or_else(|| "-".into()),
            base_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        )
        .unwrap();
        writeln!(
            out,
            "      loader={} caller={}",
            if back != 0 {
                h.object_label(back)
            } else {
                "null".into()
            },
            if caller != 0 {
                h.object_label(caller)
            } else {
                "null".into()
            }
        )
        .unwrap();
    }
}

// ---- LWJGL Upcalls ----

pub(crate) fn lwjgl_upcalls(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    writeln!(out, "\n=== LWJGL Upcalls classes").unwrap();
    for &cid in &h.classes_order {
        let name = h.class_name(cid).to_string();
        if name == "org/lwjgl/system/Upcalls" || name.starts_with("org/lwjgl/system/Upcalls$") {
            let meta = &h.classes[&cid];
            let loader = if meta.loader_id != 0 {
                h.object_label(meta.loader_id)
            } else {
                "bootstrap".into()
            };
            writeln!(out, "  {name} loader={loader}").unwrap();
            let statics: Vec<&str> = meta
                .statics
                .iter()
                .map(|(n, _)| h.strings.get(n).map(|s| &**s).unwrap_or("?"))
                .collect();
            let fields: Vec<&str> = meta
                .fields
                .iter()
                .map(|(n, _)| h.strings.get(n).map(|s| &**s).unwrap_or("?"))
                .collect();
            writeln!(out, "    statics: {}", statics.join(", ")).unwrap();
            writeln!(out, "    fields: {}", fields.join(", ")).unwrap();
        }
    }
}

// ---- console statics ----

pub(crate) fn console_statics(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    writeln!(out, "\n=== console statics").unwrap();
    for &cid in &h.classes_order {
        let name = h.class_name(cid).to_string();
        if name == "org/ohmyloader/launcher/OMLBootstrap" || name == "java/lang/System" {
            for &(name_id, value) in &h.classes[&cid].statics {
                let field = h.strings.get(&name_id).map(|s| &**s).unwrap_or("?");
                if !matches!(field, "out" | "err" | "ORIGINAL_OUT" | "ORIGINAL_ERR") {
                    continue;
                }
                let label = if value != 0 {
                    h.object_label(value)
                } else {
                    "null".into()
                };
                writeln!(out, "  class {name}.{field} -> {label}").unwrap();
            }
        }
    }
}

// ---- ClassValue entries ----

pub(crate) fn classvalue_entries(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    writeln!(out, "\n=== ClassValue entries holding session values").unwrap();
    let label_of = |v: u64| -> Option<String> {
        if target_ids.contains(&v) {
            return Some(format!("loader {}", h.object_label(v)));
        }
        if let Some(meta) = h.classes.get(&v) {
            if target_ids.contains(&meta.loader_id) {
                return Some(format!("class {}", meta.name));
            }
        }
        if let Some(ve) = h.objects.get(&v) {
            if ve.k == 1 {
                if let Some(vm) = h.classes.get(&ve.c) {
                    if target_ids.contains(&vm.loader_id) {
                        return Some(format!("instance {}", vm.name));
                    }
                }
            }
        }
        None
    };
    let mut hits = 0u32;
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 || h.class_name(e.c) != "java/lang/ClassValue$Entry" {
            continue;
        }
        let value = h
            .instance_object_field_with(ff_cache, &e, "value")
            .unwrap_or(0);
        let Some(what) = (if value != 0 { label_of(value) } else { None }) else {
            continue;
        };
        hits += 1;
        if hits <= 30 {
            writeln!(out, "  entry=0x{id:x} value=0x{value:x} -> {what}").unwrap();
        }
    }
    writeln!(out, "  total entries={hits}").unwrap();
}

// ---- ClassValue/Field deep audit ----

fn describe(
    h: &Heap,
    ff_cache: &mut HashMap<u64, Rc<Vec<FField>>>,
    target_ids: &std::collections::BTreeSet<u64>,
    id: u64,
) -> Option<String> {
    let class_loader_is_session = |cid: u64| -> bool {
        h.classes
            .get(&cid)
            .map(|m| target_ids.contains(&m.loader_id))
            .unwrap_or(false)
    };
    if id == 0 {
        return None;
    }
    if target_ids.contains(&id) {
        return Some(format!("session loader {}", h.object_label(id)));
    }
    if h.classes.contains_key(&id) && class_loader_is_session(id) {
        return Some(format!("session class {}", h.class_name(id)));
    }
    let e = h.objects.get(&id).copied()?;
    if e.k != 1 {
        return None;
    }
    let name = h.class_name(e.c).to_string();
    if class_loader_is_session(e.c) {
        return Some(format!("session instance {name}"));
    }
    let mut direct = Vec::new();
    if name.contains("MethodHandle") || name.contains("LambdaForm") {
        for f in ["staticBase", "fieldType", "clazz", "type", "member"] {
            let Some(v) = h.instance_object_field_with(ff_cache, &e, f) else {
                continue;
            };
            if v == 0 {
                continue;
            }
            if let Some(m) = h.classes.get(&v) {
                if class_loader_is_session(v)
                    || m.name.contains("BuiltInRegistries")
                    || m.name.contains("DefaultedRegistry")
                {
                    direct.push(format!("{f}={}", m.name));
                }
            } else if let Some(vo) = h.objects.get(&v) {
                if h.class_name(vo.c).contains("MemberName") {
                    let mclazz = h.instance_object_field_with(ff_cache, vo, "clazz");
                    let mname = h.instance_object_field_with(ff_cache, vo, "name");
                    let mtext = mname.and_then(|mn| h.decoded_string(mn));
                    let part = match (mname, mtext, mclazz) {
                        (_, Some(t), _) => t,
                        (None, _, Some(mc)) => h.class_name(mc).to_string(),
                        _ => "?".into(),
                    };
                    direct.push(format!(
                        "member.{}={part}",
                        if mname.is_some() { "name" } else { "clazz" }
                    ));
                }
            }
        }
    }
    if name == "java/lang/reflect/Field" {
        let clazz = h.instance_object_field_with(ff_cache, &e, "clazz");
        let fname = h.instance_object_field_with(ff_cache, &e, "name");
        let accessor = h.instance_object_field_with(ff_cache, &e, "fieldAccessor");
        let cn = clazz.map(|c| h.class_name(c)).unwrap_or("?");
        let fn2 = fname
            .and_then(|f| h.decoded_string(f))
            .unwrap_or_else(|| "?".into());
        let text = format!("{cn}.{fn2}");
        if let Some(c) = clazz {
            if h.class_name(c).contains("BuiltInRegistries") || text.contains("BuiltInRegistries") {
                let mut s = format!("Field {text}");
                if accessor.unwrap_or(0) != 0 {
                    let accn = h
                        .objects
                        .get(&accessor.unwrap())
                        .map(|a| h.class_name(a.c))
                        .unwrap_or("?");
                    s.push_str(&format!(" accessor={accn}"));
                }
                return Some(s);
            }
        }
    }
    if direct.is_empty() {
        None
    } else {
        Some(format!("{name} {}", direct.join(" ")))
    }
}

pub(crate) fn classvalue_field_deep_audit(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut cache2_own = new_map();
    let cache2 = &mut cache2_own;
    writeln!(out, "\n=== ClassValue/Field deep audit").unwrap();
    let mut entry_hits = 0u32;
    let mut map_hits = 0u32;
    let mut field_hits = 0u32;
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 {
            continue;
        }
        let name = h.class_name(e.c).to_string();
        if name == "java/lang/ClassValue$Entry" {
            let value = h
                .instance_object_field_with(ff_cache, &e, "value")
                .unwrap_or(0);
            let version = h
                .instance_object_field_with(ff_cache, &e, "version")
                .unwrap_or(0);
            let referent = if version != 0 {
                h.objects
                    .get(&version)
                    .and_then(|ve| h.instance_object_field_with(ff_cache, ve, "referent"))
                    .unwrap_or(0)
            } else {
                0
            };
            let what = describe(h, ff_cache, target_ids, value)
                .or_else(|| describe(h, ff_cache, target_ids, referent));
            if let Some(what) = what {
                entry_hits += 1;
                if entry_hits <= 40 {
                    writeln!(out, "  Entry@0x{id:x} value=0x{value:x} -> {what}").unwrap();
                }
            }
        } else if name == "java/lang/reflect/Field" {
            let clazz = h
                .instance_object_field_with(ff_cache, &e, "clazz")
                .unwrap_or(0);
            let fname = h.instance_object_field_with(ff_cache, &e, "name");
            if clazz != 0 && h.class_name(clazz).contains("BuiltInRegistries") {
                field_hits += 1;
                let accessor = h
                    .instance_object_field_with(ff_cache, &e, "fieldAccessor")
                    .unwrap_or(0);
                let fn2 = fname
                    .and_then(|f| h.decoded_string(f))
                    .unwrap_or_else(|| "?".into());
                if field_hits <= 40 {
                    let accn = h
                        .objects
                        .get(&accessor)
                        .map(|a| h.class_name(a.c))
                        .unwrap_or("null");
                    writeln!(
                        out,
                        "  Field@0x{id:x} {}.{} accessor={accn}",
                        h.class_name(clazz),
                        fn2
                    )
                    .unwrap();
                    if accessor != 0 {
                        let a = h.objects[&accessor];
                        let fields = h.flattened_fields(cache2, a.c);
                        let mut off = a.o;
                        for f in fields.iter() {
                            if f.ty != 2 {
                                off += h.type_size(f.ty) as usize;
                                continue;
                            }
                            let v = h.id_at(off);
                            off += h.id_size as usize;
                            if v == 0 {
                                continue;
                            }
                            if let Some(ve) = h.objects.get(&v) {
                                let cn = h.class_name(ve.c);
                                if cn.contains("MethodHandle")
                                    || cn.contains("LambdaForm")
                                    || cn.contains("DirectMethodHandle")
                                {
                                    writeln!(
                                        out,
                                        "      Field.accessor.{} -> {cn}@0x{v:x}",
                                        f.name
                                    )
                                    .unwrap();
                                }
                            }
                        }
                    }
                }
            }
        } else if name == "java/lang/ClassValue$ClassValueMap" {
            for array_name in ["cacheArray", "table"] {
                let Some(arr_id) = h.instance_object_field_with(ff_cache, &e, array_name) else {
                    continue;
                };
                let Some(arr) = h.objects.get(&arr_id).copied() else {
                    continue;
                };
                if arr.k != 2 {
                    continue;
                }
                for i in 0..arr.n {
                    let elem = h.id_at(arr.o + i as usize * h.id_size as usize);
                    let Some(ee) = (if elem != 0 {
                        h.objects.get(&elem).copied()
                    } else {
                        None
                    }) else {
                        continue;
                    };
                    if ee.k != 1 {
                        continue;
                    }
                    let value = h
                        .instance_object_field_with(ff_cache, &ee, "value")
                        .unwrap_or(0);
                    let Some(what) = describe(h, ff_cache, target_ids, value) else {
                        continue;
                    };
                    map_hits += 1;
                    if map_hits <= 40 {
                        writeln!(
                            out,
                            "  Map@0x{id:x} {array_name}[{i}] value=0x{value:x} -> {what}"
                        )
                        .unwrap();
                    }
                }
            }
        }
    }
    writeln!(
        out,
        "  hits: entry={entry_hits} map={map_hits} field={field_hits}"
    )
    .unwrap();
}

// ---- Reachability BFS over session classes, reused by the JNA and Soft/Final ReflectionData checks ----

fn session_classes_reachable(
    h: &Heap,
    cache2: &mut HashMap<u64, Rc<Vec<FField>>>,
    ref_cache: &mut HashMap<u64, bool>,
    target_ids: &std::collections::BTreeSet<u64>,
    start_id: u64,
    cap: usize,
) -> (Vec<String>, bool, usize) {
    let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    seen.insert(start_id);
    let mut q = vec![start_id];
    let mut found: Vec<String> = Vec::new();
    let mut found_ids: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    let mut stopped = false;
    let mut i = 0;
    while i < q.len() {
        if seen.len() > cap {
            stopped = true;
            break;
        }
        let id = q[i];
        i += 1;
        if let Some(meta) = h.classes.get(&id) {
            if target_ids.contains(&meta.loader_id) && found_ids.insert(id) {
                found.push(meta.name.clone());
            }
            continue;
        }
        let Some(e) = h.objects.get(&id).copied() else {
            continue;
        };
        let push = |v: u64, seen: &mut std::collections::BTreeSet<u64>, q: &mut Vec<u64>| {
            if v != 0 && seen.insert(v) {
                q.push(v);
            }
        };
        if e.k == 2 {
            for n in 0..e.n {
                push(
                    h.id_at(e.o + n as usize * h.id_size as usize),
                    &mut seen,
                    &mut q,
                );
            }
        } else if e.k == 1 {
            let fields = h.flattened_fields(cache2, e.c);
            let skip_referent = h.is_reference_like(ref_cache, e.c);
            let mut off = e.o;
            for f in fields.iter() {
                if f.ty == 2 {
                    let v = h.id_at(off);
                    off += h.id_size as usize;
                    if !(skip_referent && f.name == "referent") {
                        push(v, &mut seen, &mut q);
                    }
                } else {
                    off += h.type_size(f.ty) as usize;
                }
            }
        }
    }
    (found, stopped, seen.len())
}

// ---- Soft/Final referents with persistent ReflectionData owners ----
// Includes the historically orphaned "persistent JNA statics" header; its position is part of the baseline.

pub(crate) fn reflection_data_owners(ctx: &Ctx, bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut cache2_own = new_map();
    let cache2 = &mut cache2_own;
    let mut ref_cache_own = new_map();
    let ref_cache = &mut ref_cache_own;
    writeln!(out, "\n=== persistent JNA statics reaching session classes").unwrap();
    writeln!(
        out,
        "\n=== Soft/Final referents with persistent ReflectionData owners"
    )
    .unwrap();
    fn array_element(h: &Heap, array_id: u64) -> u64 {
        match h.objects.get(&array_id) {
            Some(arr) if arr.k == 2 && arr.n > 0 => h.id_at(arr.o),
            _ => 0,
        }
    }

    fn reflection_owner(
        h: &Heap,
        ff_cache: &mut HashMap<u64, Rc<Vec<FField>>>,
        ref_data: &Obj,
    ) -> u64 {
        for name in ["declaredFields", "publicFields", "declaredPublicFields"] {
            let arr = h
                .instance_object_field_with(ff_cache, ref_data, name)
                .unwrap_or(0);
            let element = if arr != 0 { array_element(h, arr) } else { 0 };
            let clazz = if element != 0 {
                h.objects
                    .get(&element)
                    .and_then(|e| h.instance_object_field_with(ff_cache, e, "clazz"))
                    .unwrap_or(0)
            } else {
                0
            };
            if clazz != 0 {
                return clazz;
            }
        }
        for name in [
            "declaredMethods",
            "publicMethods",
            "declaredPublicMethods",
            "declaredConstructors",
            "publicConstructors",
        ] {
            let arr = h
                .instance_object_field_with(ff_cache, ref_data, name)
                .unwrap_or(0);
            let element = if arr != 0 { array_element(h, arr) } else { 0 };
            let clazz = if element != 0 {
                h.objects
                    .get(&element)
                    .and_then(|e| h.instance_object_field_with(ff_cache, e, "clazz"))
                    .unwrap_or(0)
            } else {
                0
            };
            if clazz != 0 {
                return clazz;
            }
        }
        0
    }
    let mut hits = 0u32;
    let mut persistent_hits = 0u32;
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 {
            continue;
        }
        let ty = h.class_name(e.c).to_string();
        if !matches!(
            ty.as_str(),
            "java/lang/ref/SoftReference"
                | "java/lang/ref/FinalReference"
                | "java/lang/ref/Finalizer"
        ) {
            continue;
        }
        let referent = h
            .instance_object_field_with(ff_cache, &e, "referent")
            .unwrap_or(0);
        if referent == 0 {
            continue;
        }
        let Some(ref_entry) = h.objects.get(&referent).copied() else {
            continue;
        };
        if h.class_name(ref_entry.c) != "java/lang/Class$ReflectionData" {
            continue;
        }
        hits += 1;
        let owner = reflection_owner(h, ff_cache, &ref_entry);
        let Some(meta) = h.classes.get(&owner) else {
            continue;
        };
        if target_ids.contains(&meta.loader_id) {
            continue;
        }
        persistent_hits += 1;
        let (found, _, _) =
            session_classes_reachable(h, cache2, ref_cache, target_ids, referent, 50000);
        if !found.is_empty() {
            let loader = if meta.loader_id != 0 {
                h.object_label(meta.loader_id)
            } else {
                "bootstrap".into()
            };
            writeln!(
                out,
                "  {ty}@0x{id:x} reachable={} owner={} loader={loader} -> {}",
                bfs.reachable(&id),
                meta.name,
                found.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            )
            .unwrap();
        }
    }
    writeln!(
        out,
        "  reflection soft refs={hits} persistentOwners={persistent_hits}"
    )
    .unwrap();
}

// ---- JNA statics (their header is already printed by reflection_data_owners) ----

pub(crate) fn jna_statics(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut cache2_own = new_map();
    let cache2 = &mut cache2_own;
    let mut ref_cache_own = new_map();
    let ref_cache = &mut ref_cache_own;
    for &cid in &h.classes_order {
        if h.class_name(cid) != "com/sun/jna/Native" {
            continue;
        }
        for &(name_id, value) in &h.classes[&cid].statics {
            if value == 0 {
                continue;
            }
            let name = h.strings.get(&name_id).map(|s| &**s).unwrap_or("?");
            let (found, stopped, visited) =
                session_classes_reachable(h, cache2, ref_cache, target_ids, value, 300000);
            if !found.is_empty() {
                writeln!(
                    out,
                    "  static {name} -> {} session class(es), visited={visited}{}",
                    found.len(),
                    if stopped { " (capped)" } else { "" }
                )
                .unwrap();
                for n in found.iter().take(25) {
                    writeln!(out, "      {n}").unwrap();
                }
                if found.len() > 25 {
                    writeln!(out, "      ... {} more", found.len() - 25).unwrap();
                }
            }
        }
    }
}

// ---- LambdaForm$MH hidden class reverse trace ----

fn reverse_referrers(
    h: &Heap,
    cache2: &mut HashMap<u64, Rc<Vec<FField>>>,
    root_map: &HashMap<u64, Vec<String>>,
    frontier: &std::collections::BTreeSet<u64>,
) -> (Vec<(u64, u64, String)>, Vec<(u64, String)>) {
    let mut edges: Vec<(u64, u64, String)> = Vec::new();
    let mut root_hits: Vec<(u64, String)> = Vec::new();
    for (&id, labels) in root_map {
        if frontier.contains(&id) {
            for label in labels {
                root_hits.push((id, label.clone()));
            }
        }
    }
    for &cid in &h.classes_order {
        let meta = &h.classes[&cid];
        if meta.loader_id != 0 && frontier.contains(&meta.loader_id) {
            edges.push((cid, meta.loader_id, "classLoader".into()));
        }
        if meta.super_id != 0 && frontier.contains(&meta.super_id) {
            edges.push((cid, meta.super_id, "superclass".into()));
        }
        for &(name_id, value) in &meta.statics {
            if value != 0 && frontier.contains(&value) {
                let fname = h.strings.get(&name_id).map(|s| &**s).unwrap_or("?");
                edges.push((cid, value, format!("static {}.{}", meta.name, fname)));
            }
        }
        for &r in &meta.cp_refs {
            if r != 0 && frontier.contains(&r) {
                edges.push((cid, r, "constantPool".into()));
            }
        }
    }
    for (&id, &e) in &h.objects {
        if e.k == 2 {
            for i in 0..e.n {
                let v = h.id_at(e.o + i as usize * h.id_size as usize);
                if frontier.contains(&v) {
                    edges.push((id, v, format!("[{i}]")));
                }
            }
        } else if e.k == 1 {
            let fields = h.flattened_fields(cache2, e.c);
            let mut off = e.o;
            for f in fields.iter() {
                if f.ty == 2 {
                    let v = h.id_at(off);
                    off += h.id_size as usize;
                    if frontier.contains(&v) {
                        edges.push((id, v, f.name.clone()));
                    }
                } else {
                    off += h.type_size(f.ty) as usize;
                }
            }
        }
    }
    (edges, root_hits)
}

pub(crate) fn lambdaform_reverse_trace(ctx: &Ctx, _bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    let mut cache2_own = new_map();
    let cache2 = &mut cache2_own;
    writeln!(out, "\n=== LambdaForm$MH hidden class reverse trace").unwrap();
    let mut root_map: HashMap<u64, Vec<String>> = new_map();
    for r in &h.roots {
        root_map.entry(r.id).or_default().push(r.label());
    }

    let mut hidden: Vec<(u64, String, u64)> = Vec::new();
    for &cid in &h.classes_order {
        let meta = &h.classes[&cid];
        if !meta.name.starts_with("java/lang/invoke/LambdaForm$MH") {
            continue;
        }
        for &(name_id, value) in &meta.statics {
            if value == 0 {
                continue;
            }
            let Some(value_e) = h.objects.get(&value).copied() else {
                continue;
            };
            if value_e.k != 1
                || h.class_name(value_e.c) != "java/lang/invoke/DirectMethodHandle$StaticAccessor"
            {
                continue;
            }
            let field_type = h.instance_object_field_with(ff_cache, &value_e, "fieldType");
            let static_base = h.instance_object_field_with(ff_cache, &value_e, "staticBase");
            let ft_hit = field_type
                .and_then(|f| h.classes.get(&f))
                .map(|m| target_ids.contains(&m.loader_id))
                .unwrap_or(false);
            let sb_hit = static_base
                .and_then(|s| h.classes.get(&s))
                .map(|m| target_ids.contains(&m.loader_id))
                .unwrap_or(false);
            if ft_hit || sb_hit {
                hidden.push((
                    cid,
                    h.strings
                        .get(&name_id)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "?".into()),
                    value,
                ));
                break;
            }
        }
    }
    writeln!(out, "hidden LambdaForm$MH accessors={}", hidden.len()).unwrap();
    for (hcid, field, value_id) in hidden.iter().take(3) {
        writeln!(out, "\n  hidden {}@0x{hcid:x}.{field}", h.class_name(*hcid)).unwrap();
        let value = h.objects[value_id];
        let fields = h.flattened_fields(cache2, value.c);
        let mut off = value.o;
        for f in fields.iter() {
            if f.ty != 2 {
                off += h.type_size(f.ty) as usize;
                continue;
            }
            let v = h.id_at(off);
            off += h.id_size as usize;
            if v == 0 {
                continue;
            }
            let cn = match h.objects.get(&v) {
                Some(ve) => h.class_name(ve.c).to_string(),
                None => {
                    if h.classes.contains_key(&v) {
                        format!("class {}", h.class_name(v))
                    } else {
                        format!("0x{v:x}")
                    }
                }
            };
            let text = if cn == "java/lang/String" {
                json_string(&h.decoded_string(v).unwrap_or_else(|| "null".into()))
            } else {
                cn.clone()
            };
            writeln!(out, "    {} -> {text}", f.name).unwrap();
            if let Some(ve) = h.objects.get(&v).copied() {
                if h.class_name(ve.c) == "java/lang/invoke/MemberName" {
                    for mf in ["clazz", "name", "type"] {
                        let Some(mv) = h.instance_object_field_with(ff_cache, &ve, mf) else {
                            continue;
                        };
                        let mcn = match h.objects.get(&mv) {
                            Some(m) => h.class_name(m.c).to_string(),
                            None => {
                                if h.classes.contains_key(&mv) {
                                    format!("class {}", h.class_name(mv))
                                } else {
                                    "?".into()
                                }
                            }
                        };
                        let mtext = if mcn == "java/lang/String" {
                            json_string(&h.decoded_string(mv).unwrap_or_else(|| "null".into()))
                        } else {
                            mcn
                        };
                        writeln!(out, "      MemberName.{mf} -> {mtext}").unwrap();
                    }
                }
            }
        }

        let mut parent: HashMap<u64, (u64, String)> = new_map();
        let mut seen: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        seen.insert(*hcid);
        let mut frontier: Vec<u64> = vec![*hcid];
        let mut paths: Vec<String> = Vec::new();
        for _depth in 0..8 {
            if paths.len() >= 5 {
                break;
            }
            let fset: std::collections::BTreeSet<u64> = frontier.iter().copied().collect();
            let (edges, root_hits) = reverse_referrers(h, cache2, &root_map, &fset);
            let reconstruct = |node: u64, root_text: &str| -> String {
                let mut parts = Vec::new();
                let mut current = node;
                let mut guard = 0;
                while current != *hcid {
                    match parent.get(&current) {
                        Some(p) if guard < 12 => {
                            parts.push(format!("--> {} {}", p.1, h.object_label(p.0)));
                            current = p.0;
                            guard += 1;
                        }
                        _ => break,
                    }
                }
                format!(
                    "{root_text} {}{}",
                    h.object_label(node),
                    if parts.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", parts.join(" "))
                    }
                )
            };
            for (id, label) in &root_hits {
                paths.push(reconstruct(*id, &format!("[{label}]")));
            }
            for &id in &frontier {
                if let Some(labels) = root_map.get(&id) {
                    for label in labels {
                        paths.push(reconstruct(id, &format!("[{label}]")));
                    }
                }
            }
            let mut next = Vec::new();
            for (from, _to, label) in edges {
                if seen.contains(&from) {
                    continue;
                }
                seen.insert(from);
                parent.insert(from, (_to, label));
                next.push(from);
            }
            frontier = next.into_iter().take(400).collect();
            if frontier.is_empty() {
                break;
            }
        }
        if paths.is_empty() {
            writeln!(out, "    no hprof root path to the hidden Class object; its liveness is VM-internal (CLD mirror/hidden-class holder or an undumped root)").unwrap();
        } else {
            for p in paths.iter().take(5) {
                writeln!(out, "    ROOT PATH: {p}").unwrap();
            }
        }
    }
}

// ---- ApplicationShutdownHooks ----

pub(crate) fn shutdown_hooks(ctx: &Ctx, bfs: &Bfs, out: &mut Vec<u8>) {
    let h = &ctx.h;
    let target_ids = &ctx.target_ids;
    let mut ff_cache_own = new_map();
    let ff_cache = &mut ff_cache_own;
    writeln!(out, "\n=== ApplicationShutdownHooks: registered hooks").unwrap();
    let thread_super = |mut cid: u64| -> bool {
        while cid != 0 {
            if h.class_name(cid) == "java/lang/Thread" {
                return true;
            }
            cid = h.classes.get(&cid).map(|m| m.super_id).unwrap_or(0);
        }
        false
    };
    let loader_label = |cid: u64| -> String {
        let Some(meta) = h.classes.get(&cid) else {
            return "?".into();
        };
        if meta.loader_id == 0 {
            return "bootstrap".into();
        }
        format!(
            "{}{}",
            if target_ids.contains(&meta.loader_id) {
                "SESSION "
            } else {
                ""
            },
            h.object_label(meta.loader_id)
        )
    };
    let hooks_class = h
        .classes_order
        .iter()
        .find(|&&cid| h.class_name(cid) == "java/lang/ApplicationShutdownHooks")
        .copied();
    let map_id = hooks_class
        .and_then(|c| h.classes.get(&c))
        .and_then(|m| {
            m.statics
                .iter()
                .find(|(n, _)| h.strings.get(n).map(|s| &**s) == Some("hooks"))
        })
        .map(|(_, v)| *v)
        .unwrap_or(0);
    if let Some(map) = if map_id != 0 {
        h.objects.get(&map_id).copied()
    } else {
        None
    } {
        let size = h.instance_field(&map, "size").map(|v| v.1);
        let table_id = h
            .instance_object_field_with(ff_cache, &map, "table")
            .unwrap_or(0);
        let table = if table_id != 0 {
            h.objects.get(&table_id).copied()
        } else {
            None
        };
        writeln!(
            out,
            "  class java/lang/ApplicationShutdownHooks.hooks reachable={} size={}",
            bfs.reachable(&map_id),
            size.map(|v| v.to_string())
                .unwrap_or_else(|| "undefined".into())
        )
        .unwrap();
        if let Some(table) = table.filter(|t| t.k == 2) {
            let mut printed: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
            let mut n = 0u32;
            for i in 0..table.n {
                let id = h.id_at(table.o + i as usize * h.id_size as usize);
                if id == 0 || !printed.insert(id) {
                    continue;
                }
                let Some(e) = h.objects.get(&id).copied() else {
                    continue;
                };
                if e.k != 1 || !thread_super(e.c) {
                    continue;
                }
                n += 1;
                let hook_name = h
                    .instance_object_field_with(ff_cache, &e, "name")
                    .and_then(|v| h.decoded_string(v))
                    .unwrap_or_else(|| "null".into());
                let hook_name_shown = if hook_name == "null" {
                    "null".to_string()
                } else {
                    json_string(&hook_name)
                };
                let context = h
                    .instance_object_field_with(ff_cache, &e, "contextClassLoader")
                    .unwrap_or(0);
                let runnable = h
                    .instance_object_field_with(ff_cache, &e, "target")
                    .unwrap_or(0);
                let runnable_text = if runnable == 0 {
                    "none".to_string()
                } else if let Some(re) = h.objects.get(&runnable) {
                    if re.k == 1 {
                        format!("{} (loader={})", h.class_name(re.c), loader_label(re.c))
                    } else {
                        h.object_label(runnable)
                    }
                } else {
                    h.object_label(runnable)
                };
                writeln!(
                    out,
                    "  hook[{i}] {}@0x{id:x} name={hook_name_shown}",
                    h.class_name(e.c)
                )
                .unwrap();
                writeln!(
                    out,
                    "      threadClassLoader={} contextClassLoader={}",
                    loader_label(e.c),
                    if context != 0 {
                        h.object_label(context)
                    } else {
                        "null".into()
                    }
                )
                .unwrap();
                writeln!(out, "      runnable={runnable_text}").unwrap();
            }
            writeln!(out, "  registered hook threads={n}").unwrap();
        }
    } else {
        writeln!(
            out,
            "  hooks map={} (nothing registered)",
            if map_id != 0 {
                format!("0x{map_id:x}")
            } else {
                "null".into()
            }
        )
        .unwrap();
    }
    let mut ccl_hits = 0u32;
    for &id in &h.objects_order {
        let e = h.objects[&id];
        if e.k != 1 || !thread_super(e.c) {
            continue;
        }
        let ccl = h
            .instance_object_field_with(ff_cache, &e, "contextClassLoader")
            .unwrap_or(0);
        if ccl != 0 && target_ids.contains(&ccl) {
            ccl_hits += 1;
        }
    }
    writeln!(
        out,
        "  all Thread instances with a session contextClassLoader={ccl_hits}"
    )
    .unwrap();
}
