//! HPROF data model: how roots, classes, and objects are held after parsing, and the queries over them.

use super::hash::{HashMap, new_map};
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum RootKind {
    Unknown,
    JniGlobal,
    JniLocal,
    JavaFrame,
    NativeStack,
    StickyClass,
    ThreadBlock,
    MonitorUsed,
    ThreadObject,
    InternedString,
    Finalizing,
    Debugger,
    ReferenceCleanup,
    VmInternal,
    JniMonitor,
}

impl RootKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            RootKind::Unknown => "UNKNOWN",
            RootKind::JniGlobal => "JNI_GLOBAL",
            RootKind::JniLocal => "JNI_LOCAL",
            RootKind::JavaFrame => "JAVA_FRAME",
            RootKind::NativeStack => "NATIVE_STACK",
            RootKind::StickyClass => "STICKY_CLASS",
            RootKind::ThreadBlock => "THREAD_BLOCK",
            RootKind::MonitorUsed => "MONITOR_USED",
            RootKind::ThreadObject => "THREAD_OBJECT",
            RootKind::InternedString => "INTERNED_STRING",
            RootKind::Finalizing => "FINALIZING",
            RootKind::Debugger => "DEBUGGER",
            RootKind::ReferenceCleanup => "REFERENCE_CLEANUP",
            RootKind::VmInternal => "VM_INTERNAL",
            RootKind::JniMonitor => "JNI_MONITOR",
        }
    }
}

pub(crate) struct Root {
    pub(crate) kind: RootKind,
    pub(crate) id: u64,
    pub(crate) jni_ref: u64,
    pub(crate) thread: u32,
    pub(crate) depth: u32,
    pub(crate) has_thread: bool,
    pub(crate) has_depth: bool,
}

impl Root {
    pub(crate) fn label(&self) -> String {
        let mut s = self.kind.name().to_string();
        if self.has_thread {
            s.push_str(&format!(" thread={}", self.thread));
        }
        if self.has_depth {
            s.push_str(&format!(" depth={}", self.depth));
        }
        s
    }
}

pub(crate) struct ClassMeta {
    pub(crate) name: String,
    pub(crate) super_id: u64,
    pub(crate) loader_id: u64,
    /// (name string id, value). Non-object statics are skipped at parse time; a zero value is a null object reference.
    pub(crate) statics: Vec<(u64, u64)>,
    /// (name string id, basic type)
    pub(crate) fields: Vec<(u64, u8)>,
    #[allow(dead_code)]
    pub(crate) instance_size: u32,
    pub(crate) cp_refs: Vec<u64>,
}

#[derive(Clone, Copy)]
pub(crate) struct Obj {
    /// 1 = instance, 2 = object array
    pub(crate) k: u8,
    pub(crate) c: u64,
    pub(crate) o: usize,
    pub(crate) n: u32,
}

#[derive(Clone)]
pub(crate) struct FField {
    pub(crate) name: String,
    /// The field name's string id, so a BFS edge label costs no allocation.
    pub(crate) name_id: u64,
    pub(crate) ty: u8,
}

pub(crate) struct Heap {
    /// The mapped file, zero-copy; `fsmap` guarantees the `'static` lifetime.
    pub(crate) buf: &'static [u8],
    pub(crate) id_size: u32,
    pub(crate) strings: HashMap<u64, Box<str>>,
    pub(crate) loaded_class: HashMap<u64, u64>,
    pub(crate) classes: HashMap<u64, ClassMeta>,
    pub(crate) classes_order: Vec<u64>,
    pub(crate) objects: HashMap<u64, Obj>,
    pub(crate) objects_order: Vec<u64>,
    pub(crate) byte_arrays: HashMap<u64, (usize, u32)>,
    /// Every raw array, `byte[]` included: (basic type, count). Shallow size and diff use this.
    pub(crate) prim_arrays: HashMap<u64, (u8, u64)>,
    pub(crate) roots: Vec<Root>,
    pub(crate) jni_globals: Vec<u64>,
}

impl Heap {
    pub(crate) fn u16(&self, o: usize) -> u16 {
        u16::from_be_bytes([self.buf[o], self.buf[o + 1]])
    }
    pub(crate) fn u32(&self, o: usize) -> u32 {
        u32::from_be_bytes(self.buf[o..o + 4].try_into().unwrap())
    }
    pub(crate) fn id_at(&self, o: usize) -> u64 {
        if self.id_size == 8 {
            (self.u32(o) as u64) << 32 | self.u32(o + 4) as u64
        } else {
            self.u32(o) as u64
        }
    }
    pub(crate) fn type_size(&self, t: u8) -> u32 {
        match t {
            2 => self.id_size,
            4 | 8 => 1,
            5 | 9 => 2,
            6 | 10 => 4,
            7 | 11 => 8,
            _ => panic!("hprof: bad basic type {t}"),
        }
    }
    pub(crate) fn class_name(&self, cid: u64) -> &str {
        self.classes
            .get(&cid)
            .map(|m| m.name.as_str())
            .unwrap_or("?")
    }
    /// Display name for an object or a class; `None` means the caller supplies the fallback label.
    pub(crate) fn object_class_name(&self, id: u64) -> Option<String> {
        match self.objects.get(&id) {
            Some(e) => Some(if e.k == 1 {
                self.class_name(e.c).to_string()
            } else {
                format!("{}[{}]", self.class_name(e.c), e.n)
            }),
            None => {
                if self.classes.contains_key(&id) {
                    Some(format!("class {}", self.class_name(id)))
                } else {
                    None
                }
            }
        }
    }
    pub(crate) fn object_label(&self, id: u64) -> String {
        match self.object_class_name(id) {
            Some(c) => format!("{c}@0x{id:x}"),
            None => format!("?@0x{id:x}"),
        }
    }
    pub(crate) fn decoded_string(&self, id: u64) -> Option<String> {
        let e = self.objects.get(&id)?;
        if e.k != 1 || self.class_name(e.c) != "java/lang/String" {
            return None;
        }
        let value_id = self.instance_object_field(e, "value")?;
        let (bo, bn) = *self.byte_arrays.get(&value_id)?;
        let coder = self.instance_field(e, "coder").map(|v| v.1).unwrap_or(0);
        let slice = &self.buf[bo..bo + bn as usize];
        Some(if coder == 0 {
            String::from_utf8_lossy(slice).into_owned()
        } else {
            let u16s: Vec<u16> = slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
        })
    }
    /// Computes every class's flattened field table up front. Equivalent to `flattened_fields`, but each
    /// class is flattened once and shared as an `Arc`, so the BFS and the dominator tree read one copy.
    pub(crate) fn flatten_all(&self) -> HashMap<u64, std::sync::Arc<Vec<FField>>> {
        fn walk(
            h: &Heap,
            cache: &mut HashMap<u64, std::sync::Arc<Vec<FField>>>,
            cid: u64,
        ) -> std::sync::Arc<Vec<FField>> {
            if let Some(f) = cache.get(&cid) {
                return f.clone();
            }
            let mut v: Vec<FField> = Vec::new();
            if let Some(meta) = h.classes.get(&cid) {
                for (name_id, ty) in &meta.fields {
                    let name = h
                        .strings
                        .get(name_id)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("<field:{name_id}>"));
                    v.push(FField {
                        name,
                        name_id: *name_id,
                        ty: *ty,
                    });
                }
            }
            let sup = h.classes.get(&cid).map(|m| m.super_id).unwrap_or(0);
            if sup != 0 {
                let s = walk(h, cache, sup);
                v.extend(s.iter().cloned());
            }
            let a = std::sync::Arc::new(v);
            cache.insert(cid, a.clone());
            a
        }
        let mut cache: HashMap<u64, std::sync::Arc<Vec<FField>>> = new_map();
        for &cid in &self.classes_order {
            walk(self, &mut cache, cid);
        }
        cache
    }
    /// Flattened instance field layout: the class's own fields first, then the superclass chain, which is
    /// the order HPROF writes the instance bytes in.
    pub(crate) fn flattened_fields(
        &self,
        cache: &mut HashMap<u64, Rc<Vec<FField>>>,
        cid: u64,
    ) -> Rc<Vec<FField>> {
        if let Some(f) = cache.get(&cid) {
            return f.clone();
        }
        let mut v: Vec<FField> = Vec::new();
        if let Some(meta) = self.classes.get(&cid) {
            for (name_id, ty) in &meta.fields {
                let name = self
                    .strings
                    .get(name_id)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<field:{name_id}>"));
                v.push(FField {
                    name,
                    name_id: *name_id,
                    ty: *ty,
                });
            }
        }
        let sup = self.classes.get(&cid).map(|m| m.super_id).unwrap_or(0);
        if sup != 0 {
            let s = self.flattened_fields(cache, sup);
            v.extend(s.iter().cloned());
        }
        let rc = Rc::new(v);
        cache.insert(cid, rc.clone());
        rc
    }
    /// Reads a field by name as (type, value widened to u64); `type == 2` means it holds an object id.
    pub(crate) fn instance_field(&self, entry: &Obj, wanted: &str) -> Option<(u8, u64)> {
        let mut cache = new_map();
        self.instance_field_with(&mut cache, entry, wanted)
    }
    pub(crate) fn instance_field_with(
        &self,
        cache: &mut HashMap<u64, Rc<Vec<FField>>>,
        entry: &Obj,
        wanted: &str,
    ) -> Option<(u8, u64)> {
        let fields = self.flattened_fields(cache, entry.c);
        let mut off = entry.o;
        for f in fields.iter() {
            if f.name == wanted {
                let v = match f.ty {
                    2 => self.id_at(off),
                    4 | 8 => self.buf[off] as u64,
                    5 | 9 => self.u16(off) as u64,
                    6 | 10 => self.u32(off) as u64,
                    7 | 11 => (self.u32(off) as u64) << 32 | self.u32(off + 4) as u64,
                    _ => 0,
                };
                return Some((f.ty, v));
            }
            off += self.type_size(f.ty) as usize;
        }
        None
    }
    /// Reads an object-id field by name; non-object fields are stepped over.
    pub(crate) fn instance_object_field(&self, entry: &Obj, wanted: &str) -> Option<u64> {
        let mut cache = new_map();
        self.instance_object_field_with(&mut cache, entry, wanted)
    }
    pub(crate) fn instance_object_field_with(
        &self,
        cache: &mut HashMap<u64, Rc<Vec<FField>>>,
        entry: &Obj,
        wanted: &str,
    ) -> Option<u64> {
        let fields = self.flattened_fields(cache, entry.c);
        let mut off = entry.o;
        for f in fields.iter() {
            if f.ty == 2 {
                if f.name == wanted {
                    return Some(self.id_at(off));
                }
                off += self.type_size(2) as usize;
            } else {
                off += self.type_size(f.ty) as usize;
            }
        }
        None
    }
    pub(crate) fn is_reference_like(&self, cache: &mut HashMap<u64, bool>, mut cid: u64) -> bool {
        if let Some(&v) = cache.get(&cid) {
            return v;
        }
        let start = cid;
        let mut v = false;
        while cid != 0 {
            if self.class_name(cid) == "java/lang/ref/Reference" {
                v = true;
                break;
            }
            cid = self.classes.get(&cid).map(|m| m.super_id).unwrap_or(0);
        }
        cache.insert(start, v);
        v
    }
    pub(crate) fn is_final_reference(&self, cache: &mut HashMap<u64, bool>, mut cid: u64) -> bool {
        if let Some(&v) = cache.get(&cid) {
            return v;
        }
        let start = cid;
        let mut v = false;
        while cid != 0 {
            if self.class_name(cid) == "java/lang/ref/FinalReference" {
                v = true;
                break;
            }
            cid = self.classes.get(&cid).map(|m| m.super_id).unwrap_or(0);
        }
        cache.insert(start, v);
        v
    }
}

/// The `JSON.stringify` escaping the string output is compared against.
pub(crate) fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
