//! `hprof-soft`: shortest strong-reference path from the GC roots to instances of one named class. Its
//! output is byte-identical to the tool it replaces, verified by diff on a real 418MB dump across the
//! `default`, `not-found`, and `inspect` paths.
//!
//! It is deliberately **not** built on the main `hprof` BFS, because the graph semantics differ:
//!   - class-node edges include `protectionDomain` and carry no constant-pool references;
//!   - instances and object arrays carry no `Class` edge;
//!   - of the `referent` edges, `SoftReference` keeps its target and every other `Reference` skips it;
//!   - raw arrays are graph nodes (leaves);
//!   - seeding is VM roots plus the class mirrors of loaders that are still alive, excluding the mirrors of
//!     `SessionClassLoader` and `OMLClassLoader`.
//! Two implementations that disagree are a bug hunt; two that agree are evidence, which is the point of
//! keeping them apart.
//!
//! To reproduce the original output order, `JavaMap` reimplements `java.util.HashMap` iteration order for
//! the put-only case: tail insertion, resize at 0.75 load, and the split-into-lo/hi-chains rehash that
//! preserves each chain's order. Treeified buckets do not change the `next`-chain iteration order, so no
//! red-black tree is needed.

use super::super::fsmap;

const K_INSTANCE: u8 = 1;
const K_OBJ_ARRAY: u8 = 2;
const K_PRIM_ARRAY: u8 = 3;
const K_CLASS: u8 = 4;

struct Field {
    name: Option<String>,
    ty: u8,
}

struct StaticField {
    name: Option<String>,
    ty: u8,
    value: u64,
}

struct ClassInfo {
    name: Option<String>,
    super_id: u64,
    loader_id: u64,
    pd_id: u64,
    inst: Vec<Field>,
    statics: Vec<StaticField>,
    /// The flattened field chain, subclass fields first; computed once and cached here.
    flat: Option<std::rc::Rc<Vec<(Option<String>, u8)>>>,
}

impl ClassInfo {
    fn new() -> Self {
        ClassInfo {
            name: None,
            super_id: 0,
            loader_id: 0,
            pd_id: 0,
            inst: Vec::new(),
            statics: Vec::new(),
            flat: None,
        }
    }
}

/// `java.util.HashMap` iteration order, reproduced for the put-only case: no removals, and treeification
/// changes a bucket's internals but not the `next` chain that the iteration order follows, so chains are
/// enough.
struct JavaMap<K: JavaHash + PartialEq + Clone, V> {
    bins: Vec<Vec<(K, V)>>,
    size: usize,
}

trait JavaHash {
    /// The JDK's hashCode contract, as the i32 bit pattern Java computes.
    fn jhash(&self) -> i32;
}

impl JavaHash for u64 {
    fn jhash(&self) -> i32 {
        (self ^ (self >> 32)) as i32
    }
}

impl JavaHash for String {
    fn jhash(&self) -> i32 {
        // String.hashCode folds over UTF-16 code units, not over code points.
        let mut h: i32 = 0;
        for u in self.encode_utf16() {
            h = h.wrapping_mul(31).wrapping_add(u as i32);
        }
        h
    }
}

impl<K: JavaHash + PartialEq + Clone, V> JavaMap<K, V> {
    fn new() -> Self {
        JavaMap {
            bins: Vec::new(),
            size: 0,
        }
    }

    fn spread(h: i32) -> usize {
        let h = h as u32;
        (h ^ (h >> 16)) as usize
    }

    fn bin_of(&self, k: &K) -> Option<usize> {
        if self.bins.is_empty() {
            return None;
        }
        let i = Self::spread(k.jhash()) & (self.bins.len() - 1);
        if self.bins[i].iter().any(|(ek, _)| ek == k) {
            Some(i)
        } else {
            None
        }
    }

    fn get(&self, k: &K) -> Option<&V> {
        let i = self.bin_of(k)?;
        self.bins[i].iter().find(|(ek, _)| ek == k).map(|(_, v)| v)
    }

    fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let i = self.bin_of(k)?;
        self.bins[i]
            .iter_mut()
            .find(|(ek, _)| ek == k)
            .map(|(_, v)| v)
    }

    /// `computeIfAbsent`: insert when missing, check the load factor, and hand back a mutable reference.
    fn get_or_insert(&mut self, k: K, make: impl FnOnce() -> V) -> &mut V {
        let probe = k.clone();
        if self.get(&probe).is_none() {
            if self.bins.is_empty() {
                self.bins = (0..16).map(|_| Vec::new()).collect();
            }
            let i = Self::spread(k.jhash()) & (self.bins.len() - 1);
            self.bins[i].push((k, make()));
            self.size += 1;
            // Java inserts first, then resizes once size exceeds 0.75 * capacity.
            if self.size * 4 > self.bins.len() * 3 {
                self.resize();
            }
        }
        let i = self.bin_of(&probe).unwrap();
        let pos = self.bins[i]
            .iter()
            .position(|(ek, _)| *ek == probe)
            .unwrap();
        &mut self.bins[i][pos].1
    }

    /// Java `put`: overwrite an existing key in place.
    fn insert(&mut self, k: K, v: V) {
        let probe = k.clone();
        if let Some(slot) = self.get_mut(&probe) {
            *slot = v;
            return;
        }
        if self.bins.is_empty() {
            self.bins = (0..16).map(|_| Vec::new()).collect();
        }
        let i = Self::spread(k.jhash()) & (self.bins.len() - 1);
        self.bins[i].push((k, v));
        self.size += 1;
        if self.size * 4 > self.bins.len() * 3 {
            self.resize();
        }
    }

    /// Java resize: split each chain on the new high bit, keeping the order within the lo and hi halves.
    fn resize(&mut self) {
        let old = std::mem::take(&mut self.bins);
        let old_cap = old.len();
        self.bins = (0..old_cap * 2).map(|_| Vec::new()).collect();
        for (j, bin) in old.into_iter().enumerate() {
            for (k, v) in bin {
                let i = if Self::spread(k.jhash()) & old_cap != 0 {
                    j + old_cap
                } else {
                    j
                };
                self.bins[i].push((k, v));
            }
        }
    }

    fn len(&self) -> usize {
        self.size
    }

    fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.bins.iter().flatten()
    }
}

/// Open-addressed table keyed by the mmh3 finalizer. Its quirks are load-bearing and stay: zero is the
/// empty-slot sentinel, and a grow re-inserts in the existing order.
struct LongIntMap {
    keys: Vec<u64>,
    vals: Vec<i32>,
    mask: usize,
    size: usize,
}

fn highest_one_bit(x: usize) -> usize {
    if x == 0 {
        0
    } else {
        1 << (usize::BITS - 1 - x.leading_zeros())
    }
}

impl LongIntMap {
    fn new(cap: usize) -> Self {
        let c = highest_one_bit(usize::max(16, cap - 1)) * 2;
        LongIntMap {
            keys: vec![0; c],
            vals: vec![0; c],
            mask: c - 1,
            size: 0,
        }
    }

    fn put(&mut self, k: u64, v: i32) {
        if self.size * 10 > self.keys.len() * 6 {
            self.grow();
        }
        let mut i = mix(k) & self.mask;
        while self.keys[i] != 0 {
            if self.keys[i] == k {
                self.vals[i] = v;
                return;
            }
            i = (i + 1) & self.mask;
        }
        self.keys[i] = k;
        self.vals[i] = v;
        self.size += 1;
    }

    fn get(&self, k: u64) -> Option<i32> {
        let mut i = mix(k) & self.mask;
        while self.keys[i] != 0 {
            if self.keys[i] == k {
                return Some(self.vals[i]);
            }
            i = (i + 1) & self.mask;
        }
        None
    }

    fn grow(&mut self) {
        let ok = std::mem::take(&mut self.keys);
        let ov = std::mem::take(&mut self.vals);
        self.keys = vec![0; ok.len() * 2];
        self.vals = vec![0; ov.len() * 2];
        self.mask = self.keys.len() - 1;
        self.size = 0;
        for (i, &k) in ok.iter().enumerate() {
            if k != 0 {
                self.put(k, ov[i]);
            }
        }
    }
}

fn mix(mut k: u64) -> usize {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    // Java truncates to (int); after truncation the low 32 bits of the mask agree with Java's.
    k as usize
}

struct Soft {
    b: &'static [u8],
    id_size: usize,
    oid: Vec<u64>,
    ocls: Vec<u64>,
    ooff: Vec<usize>,
    olen: Vec<usize>,
    okind: Vec<u8>,
    obj_count: usize,
    index: LongIntMap,
    strings: std::collections::HashMap<u64, String>,
    classes: JavaMap<u64, ClassInfo>,
    roots: Vec<(u64, String)>,
    root_seen: std::collections::HashSet<u64>,
    root_label_of: std::collections::HashMap<usize, String>,
}

fn ru8(b: &[u8], p: usize) -> u8 {
    b[p]
}
fn ri8(b: &[u8], p: usize) -> i64 {
    b[p] as i8 as i64
}
fn ru32(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}
fn ru16(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}
fn ri16(b: &[u8], p: usize) -> i64 {
    i16::from_be_bytes([b[p], b[p + 1]]) as i64
}
fn ri32(b: &[u8], p: usize) -> i64 {
    i32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as i64
}
fn ru64(b: &[u8], p: usize) -> u64 {
    u64::from_be_bytes(b[p..p + 8].try_into().unwrap())
}

impl Soft {
    fn new(b: &'static [u8]) -> Self {
        Soft {
            b,
            id_size: 0,
            oid: vec![0; 1 << 20],
            ocls: vec![0; 1 << 20],
            ooff: vec![0; 1 << 20],
            olen: vec![0; 1 << 20],
            okind: vec![0; 1 << 20],
            obj_count: 0,
            index: LongIntMap::new(1 << 22),
            strings: std::collections::HashMap::new(),
            classes: JavaMap::new(),
            roots: Vec::new(),
            root_seen: std::collections::HashSet::new(),
            root_label_of: std::collections::HashMap::new(),
        }
    }

    fn size_of(&self, t: u8) -> usize {
        match t {
            2 => self.id_size,
            4 | 8 => 1,
            5 | 9 => 2,
            6 | 10 => 4,
            7 | 11 => 8,
            _ => panic!("type {t}"),
        }
    }

    /// Returns the offset where the record area starts.
    fn parse_header(&mut self) -> usize {
        let b = self.b;
        let mut p = 0;
        while ru8(b, p) != 0 {
            p += 1;
        }
        let version = String::from_utf8_lossy(&b[..p]).into_owned();
        p += 1; // NUL
        self.id_size = ru32(b, p) as usize;
        eprintln!("hprof {version} idSize={}", self.id_size);
        p + 4 + 8 // past the idSize field and the timestamp
    }

    fn parse_records(&mut self, mut p: usize) {
        let b = self.b;
        while b.len() - p >= 9 {
            let tag = ru8(b, p);
            p += 1;
            p += 4; // time
            let len = ri32(b, p) as usize;
            p += 4;
            let body = p;
            let end = body + len;
            match tag {
                0x01 => {
                    let id = ru64(b, body);
                    let raw = &b[body + self.id_size..end];
                    self.strings
                        .insert(id, String::from_utf8_lossy(raw).into_owned());
                }
                0x02 => {
                    let class_id = ru64(b, body + 4);
                    let name_id = ru64(b, body + 4 + self.id_size + 4);
                    let name = self.strings.get(&name_id).cloned();
                    let ci = self.classes.get_or_insert(class_id, ClassInfo::new);
                    ci.name = name;
                }
                0x0C | 0x1C => self.parse_heap(body, end),
                _ => {}
            }
            p = end;
        }
    }

    fn add_root(&mut self, id: u64, label: String) {
        if id == 0 {
            return;
        }
        // putIfAbsent: the first label recorded for an id is the one that stays.
        if self.root_seen.insert(id) {
            self.roots.push((id, label));
        }
    }

    fn add_object(&mut self, id: u64, class_id: u64, off: usize, len: usize, kind: u8) {
        if self.obj_count == self.oid.len() {
            let cap = self.oid.len() * 2;
            self.oid.resize(cap, 0);
            self.ocls.resize(cap, 0);
            self.ooff.resize(cap, 0);
            self.olen.resize(cap, 0);
            self.okind.resize(cap, 0);
        }
        let i = self.obj_count;
        self.obj_count += 1;
        self.oid[i] = id;
        self.ocls[i] = class_id;
        self.ooff[i] = off;
        self.olen[i] = len;
        self.okind[i] = kind;
        self.index.put(id, i as i32);
    }

    fn parse_heap(&mut self, start: usize, end: usize) {
        let b = self.b;
        let ids = self.id_size;
        let mut p = start;
        while p < end {
            let tag = ru8(b, p);
            p += 1;
            match tag {
                0xFF | 0x05 | 0x07 | 0x89 | 0x8A | 0x8B | 0x8C | 0x8D | 0x90 => {
                    let id = ru64(b, p);
                    p += ids;
                    self.add_root(id, root_name(tag).into());
                }
                0x01 => {
                    let id = ru64(b, p);
                    p += ids * 2;
                    self.add_root(id, "JNI_GLOBAL".into());
                }
                0x02 | 0x03 => {
                    let id = ru64(b, p);
                    p += ids;
                    let thread = ri32(b, p);
                    p += 4;
                    let depth = ri32(b, p);
                    p += 4;
                    let kind = if tag == 0x02 {
                        "JNI_LOCAL"
                    } else {
                        "JAVA_FRAME"
                    };
                    self.add_root(id, format!("{kind} thread={thread} depth={depth}"));
                }
                0x04 | 0x06 => {
                    let id = ru64(b, p);
                    p += ids;
                    let thread = ri32(b, p);
                    p += 4;
                    let kind = if tag == 0x04 {
                        "NATIVE_STACK"
                    } else {
                        "THREAD_BLOCK"
                    };
                    self.add_root(id, format!("{kind} thread={thread}"));
                }
                0x08 => {
                    let id = ru64(b, p);
                    p += ids;
                    let thread = ri32(b, p);
                    p += 8;
                    self.add_root(id, format!("THREAD_OBJECT thread={thread}"));
                }
                0x8E => {
                    let id = ru64(b, p);
                    p += ids;
                    let thread = ri32(b, p);
                    p += 4;
                    let depth = ri32(b, p);
                    p += 4;
                    self.add_root(id, format!("JNI_MONITOR thread={thread} depth={depth}"));
                }
                0xFE => {
                    p += 4 + ids;
                }
                0x20 => {
                    let class_id = ru64(b, p);
                    p += ids;
                    p += 4; // trace serial
                    let super_id = ru64(b, p);
                    p += ids;
                    let loader_id = ru64(b, p);
                    p += ids;
                    p += ids; // signers
                    let pd_id = ru64(b, p);
                    p += ids;
                    p += ids * 2; // reserved
                    p += 4; // instance size
                    let cp_count = ru16(b, p) as usize;
                    p += 2;
                    for _ in 0..cp_count {
                        p += 2; // pool index
                        let t = ru8(b, p);
                        p += 1;
                        p += self.size_of(t);
                    }
                    let static_count = ru16(b, p) as usize;
                    p += 2;
                    let mut statics = Vec::with_capacity(static_count);
                    for _ in 0..static_count {
                        let name_id = ru64(b, p);
                        p += ids;
                        let t = ru8(b, p);
                        p += 1;
                        let v;
                        if t == 2 {
                            v = ru64(b, p);
                            p += ids;
                        } else {
                            let sz = self.size_of(t);
                            v = match sz {
                                4 => ri32(b, p) as u32 as u64,
                                8 => ru64(b, p),
                                2 => ri16(b, p) as u64,
                                _ => ri8(b, p) as u64,
                            };
                            p += sz;
                        }
                        statics.push(StaticField {
                            name: self.strings.get(&name_id).cloned(),
                            ty: t,
                            value: v,
                        });
                    }
                    let field_count = ru16(b, p) as usize;
                    p += 2;
                    let mut inst = Vec::with_capacity(field_count);
                    for _ in 0..field_count {
                        let name_id = ru64(b, p);
                        p += ids;
                        let t = ru8(b, p);
                        p += 1;
                        inst.push(Field {
                            name: self.strings.get(&name_id).cloned(),
                            ty: t,
                        });
                    }
                    {
                        let ci = self.classes.get_or_insert(class_id, ClassInfo::new);
                        ci.super_id = super_id;
                        ci.loader_id = loader_id;
                        ci.pd_id = pd_id;
                        ci.inst = inst;
                        ci.statics = statics;
                        ci.flat = None;
                    }
                    self.add_object(class_id, 0, p, 0, K_CLASS);
                }
                0x21 => {
                    let id = ru64(b, p);
                    p += ids;
                    p += 4;
                    let class_id = ru64(b, p);
                    p += ids;
                    let num_bytes = ri32(b, p) as usize;
                    p += 4;
                    self.add_object(id, class_id, p, num_bytes, K_INSTANCE);
                    p += num_bytes;
                }
                0x22 => {
                    let id = ru64(b, p);
                    p += ids;
                    p += 4;
                    let count = ri32(b, p) as usize;
                    p += 4;
                    let class_id = ru64(b, p);
                    p += ids;
                    self.add_object(id, class_id, p, count * ids, K_OBJ_ARRAY);
                    p += count * ids;
                }
                0x23 => {
                    let id = ru64(b, p);
                    p += ids;
                    p += 4;
                    let count = ri32(b, p) as usize;
                    p += 4;
                    let ty = ru8(b, p);
                    p += 1;
                    let bytes = count * self.size_of(ty);
                    self.add_object(id, 0, p, bytes, K_PRIM_ARRAY);
                    p += bytes;
                }
                _ => panic!("unknown heap subtag 0x{tag:x} at {}", p - 1),
            }
        }
    }

    fn idx_of(&self, id: u64) -> i32 {
        if id == 0 || id == u64::MAX {
            return -1;
        }
        self.index.get(id).unwrap_or(-1)
    }

    /// The flattened field chain, subclass fields first, cached per class. The walk stops after 64 classes,
    /// which is the depth limit the byte-identical output was measured against.
    fn flatten(&mut self, cid: u64) -> std::rc::Rc<Vec<(Option<String>, u8)>> {
        if let Some(c) = self.classes.get(&cid) {
            if let Some(f) = &c.flat {
                return f.clone();
            }
        }
        let mut list = Vec::new();
        let mut cur = Some(cid);
        let mut guard = 0usize;
        while let Some(id) = cur {
            if guard >= 64 {
                break;
            }
            guard += 1;
            let Some(ci) = self.classes.get(&id) else {
                break;
            };
            // HPROF writes instance fields with the class's own fields first and the superclass fields after.
            list.extend(ci.inst.iter().map(|f| (f.name.clone(), f.ty)));
            cur = if ci.super_id != 0 {
                Some(ci.super_id)
            } else {
                None
            };
        }
        let rc = std::rc::Rc::new(list);
        if let Some(c) = self.classes.get_mut(&cid) {
            c.flat = Some(rc.clone());
        }
        rc
    }

    fn is_reference_type(&self, cid: u64) -> bool {
        let mut cur = Some(cid);
        let mut guard = 0usize;
        while let Some(id) = cur {
            if guard >= 64 {
                break;
            }
            guard += 1;
            let Some(ci) = self.classes.get(&id) else {
                break;
            };
            if ci.name.as_deref() == Some("java/lang/ref/Reference") {
                return true;
            }
            cur = if ci.super_id != 0 {
                Some(ci.super_id)
            } else {
                None
            };
        }
        false
    }

    fn is_soft_reference_type(&self, cid: u64) -> bool {
        let mut cur = Some(cid);
        let mut guard = 0usize;
        while let Some(id) = cur {
            if guard >= 64 {
                break;
            }
            guard += 1;
            let Some(ci) = self.classes.get(&id) else {
                break;
            };
            if ci.name.as_deref() == Some("java/lang/ref/SoftReference") {
                return true;
            }
            if ci.name.as_deref() == Some("java/lang/ref/Reference") {
                return false;
            }
            cur = if ci.super_id != 0 {
                Some(ci.super_id)
            } else {
                None
            };
        }
        false
    }

    fn loader_class_name_of(&self, loader_id: u64) -> Option<String> {
        if loader_id == 0 {
            return None;
        }
        let li = self.index.get(loader_id)?;
        self.classes
            .get(&self.ocls[li as usize])
            .and_then(|c| c.name.clone())
    }

    fn ref_capacity(&mut self, i: usize) -> usize {
        match self.okind[i] {
            K_OBJ_ARRAY => usize::max(4, self.olen[i] / self.id_size),
            K_CLASS => {
                8 + self
                    .classes
                    .get(&self.oid[i])
                    .map(|c| c.statics.len())
                    .unwrap_or(0)
            }
            K_INSTANCE => {
                let cid = self.ocls[i];
                if self.classes.get(&cid).is_none() {
                    8
                } else {
                    usize::max(8, self.flatten(cid).len())
                }
            }
            _ => 4,
        }
    }

    /// Fills `out` and `out_code` and returns the edge count. `code` is the reference ordinal the original
    /// implementation used, which the output order depends on.
    fn expand(&mut self, i: usize, out: &mut [i32], out_code: &mut [i32]) -> usize {
        let b = self.b;
        let mut n = 0usize;
        let kind = self.okind[i];
        let start = self.ooff[i];
        let len = self.olen[i];
        if kind == K_INSTANCE {
            let cid = self.ocls[i];
            if self.classes.get(&cid).is_none() {
                return 0;
            }
            let flat = self.flatten(cid);
            let reference = self.is_reference_type(cid);
            let soft = self.is_soft_reference_type(cid);
            let mut p = start;
            for (f, (fname, fty)) in flat.iter().enumerate() {
                if *fty == 2 {
                    let child = ru64(b, p);
                    p += self.id_size;
                    // A SoftReference keeps its referent; every other Reference subtype skips it here.
                    if !(reference && !soft && fname.as_deref() == Some("referent")) {
                        out[n] = self.idx_of(child);
                        out_code[n] = f as i32;
                        n += 1;
                    }
                } else {
                    p += self.size_of(*fty);
                }
                if p > start + len {
                    break;
                }
            }
        } else if kind == K_OBJ_ARRAY {
            let mut p = start;
            let count = len / self.id_size;
            for k in 0..count {
                out[n] = self.idx_of(ru64(b, p));
                out_code[n] = k as i32;
                n += 1;
                p += self.id_size;
            }
        } else if kind == K_CLASS {
            let cid = self.oid[i];
            let (super_id, loader_id, pd_id, statics): (u64, u64, u64, Vec<(u8, u64)>) = {
                let Some(ci) = self.classes.get(&cid) else {
                    return 0;
                };
                (
                    ci.super_id,
                    ci.loader_id,
                    ci.pd_id,
                    ci.statics.iter().map(|s| (s.ty, s.value)).collect(),
                )
            };
            // Code 0 is reserved for the superclass edge; the statics follow it.
            out[n] = self.idx_of(super_id);
            out_code[n] = 0;
            n += 1;
            out[n] = self.idx_of(loader_id);
            out_code[n] = 1;
            n += 1;
            out[n] = self.idx_of(pd_id);
            out_code[n] = 1000;
            n += 1;
            for (j, (ty, value)) in statics.iter().enumerate() {
                if *ty == 2 {
                    out[n] = self.idx_of(*value);
                    out_code[n] = (2 + j) as i32;
                    n += 1;
                }
            }
        }
        n
    }

    fn class_name_of(&self, i: usize) -> String {
        match self.okind[i] {
            K_CLASS => {
                let inner = match self.classes.get(&self.oid[i]) {
                    None => "?".to_string(),
                    Some(c) => c.name.clone().unwrap_or_else(|| "null".into()),
                };
                format!("java.lang.Class<{inner}>")
            }
            K_OBJ_ARRAY => {
                let inner = match self.classes.get(&self.ocls[i]) {
                    None => "Object".to_string(),
                    Some(c) => c.name.clone().unwrap_or_else(|| "null".into()),
                };
                format!("{inner}[]")
            }
            K_PRIM_ARRAY => {
                let inner = match self.classes.get(&self.ocls[i]) {
                    None => "prim".to_string(),
                    Some(c) => c.name.clone().unwrap_or_else(|| "null".into()),
                };
                format!("{inner} (primitive array)")
            }
            _ => match self.classes.get(&self.ocls[i]).and_then(|c| c.name.clone()) {
                Some(n) => n,
                None => format!("classId=0x{:x}", self.ocls[i] & 0xffff_ffff),
            },
        }
    }

    fn edge_label(&mut self, parent: usize, code: i32) -> String {
        let kind = self.okind[parent];
        if kind == K_OBJ_ARRAY {
            return format!("[{code}]");
        }
        if kind == K_CLASS {
            if code == 0 {
                return "super".into();
            }
            if code == 1 {
                return "classLoader".into();
            }
            if code == 1000 {
                return "protectionDomain".into();
            }
            if let Some(ci) = self.classes.get(&self.oid[parent]) {
                let idx = code - 2;
                if idx >= 0 && (idx as usize) < ci.statics.len() {
                    let name = ci.statics[idx as usize]
                        .name
                        .clone()
                        .unwrap_or_else(|| "null".into());
                    return format!("static {name}");
                }
            }
            return format!("class-meta#{code}");
        }
        let cid = self.ocls[parent];
        if self.classes.get(&cid).is_none() {
            return format!("?{code}");
        }
        let flat = self.flatten(cid);
        if code >= 0 && (code as usize) < flat.len() {
            flat[code as usize]
                .0
                .clone()
                .unwrap_or_else(|| format!("field#{code}"))
        } else {
            format!("field#{code}")
        }
    }

    fn print_path(&mut self, target: usize, prev: &[i32], code: &[i32]) {
        let mut lines: Vec<String> = Vec::new();
        let mut cur = target as i32;
        let mut guard = 0u32;
        while cur != -2 && cur >= 0 && guard < 100000 {
            guard += 1;
            let cls = self.class_name_of(cur as usize);
            let line = format!("[{cur}] {cls}");
            if prev[cur as usize] == -2 {
                let label = self
                    .root_label_of
                    .get(&(cur as usize))
                    .cloned()
                    .unwrap_or_else(|| "(root)".into());
                lines.insert(0, format!("{line}   <= ROOT {label}"));
                break;
            }
            let el = self.edge_label(prev[cur as usize] as usize, code[cur as usize]);
            lines.insert(0, format!("{line}   <= {el}"));
            cur = prev[cur as usize];
        }
        for l in &lines {
            println!("{l}");
        }
    }
}

fn root_name(tag: u8) -> &'static str {
    match tag {
        0xFF => "UNKNOWN",
        0x05 => "STICKY_CLASS",
        0x07 => "MONITOR_USED",
        0x89 => "INTERNED_STRING",
        0x8A => "FINALIZING",
        0x8B => "DEBUGGER",
        0x8C => "REFERENCE_CLEANUP",
        0x8D => "VM_INTERNAL",
        0x90 => "UNREACHABLE",
        _ => "ROOT_TAG",
    }
}

/// `hprof-soft <dump.hprof> <Target.Class> [extra...]`. When `extra` starts with `inspect`, the field
/// values of the target class's first three instances are printed as well.
pub fn run(file: &str, target: &str, extra: &[String]) -> Result<(), String> {
    let target = target.replace('.', "/");
    let inspect = extra.first().map(|s| s.as_str()) == Some("inspect");
    let b = fsmap::map_file(file)?;
    let mut s = Soft::new(b);
    let rec_start = s.parse_header();
    s.parse_records(rec_start);
    eprintln!(
        "objects={} classes={} roots={}",
        s.obj_count,
        s.classes.len(),
        s.roots.len()
    );

    if inspect {
        let mut seen_n = 0usize;
        for i in 0..s.obj_count {
            if seen_n >= 3 {
                break;
            }
            if s.okind[i] != K_INSTANCE {
                continue;
            }
            let Some(name) = s.classes.get(&s.ocls[i]).and_then(|c| c.name.clone()) else {
                continue;
            };
            if name != target {
                continue;
            }
            seen_n += 1;
            println!("instance {i} len={} class={name}", s.olen[i]);
            let flat = s.flatten(s.ocls[i]);
            let mut p = s.ooff[i];
            let end = s.ooff[i] + s.olen[i];
            for (fname, fty) in flat.iter() {
                if *fty == 2 {
                    if p + s.id_size > end {
                        println!("  <truncated>");
                        break;
                    }
                    let child = ru64(s.b, p);
                    p += s.id_size;
                    let cn = match s.index.get(child) {
                        None => format!("(dangling 0x{child:x})"),
                        Some(c) => s.class_name_of(c as usize),
                    };
                    println!("  {} = {cn}", fname.as_deref().unwrap_or("null"));
                } else {
                    p += s.size_of(*fty);
                }
            }
        }
        return Ok(());
    }

    let mut target_i: i32 = -1;
    for i in 0..s.obj_count {
        if s.okind[i] == K_INSTANCE {
            if let Some(ci) = s.classes.get(&s.ocls[i]) {
                if ci.name.as_deref() == Some(target.as_str()) {
                    target_i = i as i32;
                    break;
                }
            }
        }
    }
    if target_i < 0 {
        println!("target not found: {target}");
        let mut nulls = 0usize;
        for (_, ci) in s.classes.iter() {
            match &ci.name {
                None => nulls += 1,
                Some(n) if n.contains("ohmyloader") => println!("  class: {n} id=0x0"),
                _ => {}
            }
        }
        println!("  unnamed classes: {nulls}");
        return Ok(());
    }
    println!(
        "target idx={} id=0x{:x} class={target}",
        target_i, s.oid[target_i as usize]
    );

    let obj_count = s.obj_count;
    let mut seen = vec![false; obj_count];
    let mut prev = vec![-1i32; obj_count];
    let mut code = vec![0i32; obj_count];
    let mut queue = vec![0i32; obj_count];
    let (mut head, mut tail) = (0usize, 0usize);

    // Seeding 1: the VM roots, in record order, keeping the first label per id.
    let roots = s.roots.clone();
    for (id, label) in roots {
        let Some(idx) = s.index.get(id) else { continue };
        let i = idx as usize;
        if seen[i] {
            continue;
        }
        seen[i] = true;
        prev[i] = -2;
        code[i] = 0;
        s.root_label_of.insert(i, label);
        queue[tail] = i as i32;
        tail += 1;
        if i as i32 == target_i {
            s.print_path(target_i as usize, &prev, &code);
            return Ok(());
        }
    }
    // Seeding 2: the class mirrors of loaders that are still alive, the OML loaders excluded — their statics
    // count as strong roots.
    for i in 0..obj_count {
        if s.okind[i] != K_CLASS {
            continue;
        }
        let loader_id = match s.classes.get(&s.oid[i]) {
            Some(c) => c.loader_id,
            None => continue,
        };
        if seen[i] {
            continue;
        }
        let ln = s.loader_class_name_of(loader_id);
        if ln
            .as_deref()
            .is_some_and(|n| n.contains("SessionClassLoader") || n.contains("OMLClassLoader"))
        {
            continue;
        }
        seen[i] = true;
        prev[i] = -2;
        code[i] = 0;
        s.root_label_of.insert(i, "CLASS_STATIC".into());
        queue[tail] = i as i32;
        tail += 1;
    }
    while head < tail {
        let cur = queue[head] as usize;
        head += 1;
        let cap = s.ref_capacity(cur);
        let mut out = vec![0i32; cap];
        let mut out_code = vec![0i32; cap];
        let n = s.expand(cur, &mut out, &mut out_code);
        for k in 0..n {
            let child = out[k];
            if child < 0 || child as usize >= obj_count || seen[child as usize] {
                continue;
            }
            let c = child as usize;
            seen[c] = true;
            prev[c] = cur as i32;
            code[c] = out_code[k];
            if c as i32 == target_i {
                s.print_path(c, &prev, &code);
                return Ok(());
            }
            queue[tail] = child;
            tail += 1;
        }
    }
    println!(
        "no root path found (target may only be weakly reachable); reachable={tail}/{obj_count} roots={}",
        s.roots.len()
    );
    let mut kinds: std::collections::BTreeMap<String, i32> = std::collections::BTreeMap::new();
    for (_, label) in &s.roots {
        let k = label.split(' ').next().unwrap_or("").to_string();
        *kinds.entry(k).or_insert(0) += 1;
    }
    let body: Vec<String> = kinds.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("root kinds: {{{}}}", body.join(", "));
    let mut unr: JavaMap<String, i32> = JavaMap::new();
    for i in 0..obj_count {
        if seen[i] {
            continue;
        }
        let cn = s.class_name_of(i);
        match unr.get_mut(&cn) {
            Some(v) => *v += 1,
            None => unr.insert(cn, 1),
        }
    }
    let mut entries: Vec<_> = unr.iter().collect();
    // A stable sort, so equal counts keep the JavaMap (= java.util.HashMap) iteration order they arrived in.
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, v) in entries.into_iter().take(15) {
        println!("  unreachable {v} x {k}");
    }
    Ok(())
}
