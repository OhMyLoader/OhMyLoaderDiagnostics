//! HPROF 1.0.2 parsing: zero-copy over the mmap, one sequential pass building the indexes.

use super::hash::new_map;
use std::time::Instant;

use super::model::{ClassMeta, Heap, Obj, Root, RootKind};

pub(crate) fn parse(path: &str) -> Result<Heap, String> {
    let buf = crate::fsmap::map_file(path)?;
    let t0 = Instant::now();
    let mut h = Heap {
        buf,
        id_size: 8,
        strings: new_map(),
        loaded_class: new_map(),
        classes: new_map(),
        classes_order: Vec::new(),
        objects: new_map(),
        objects_order: Vec::new(),
        byte_arrays: new_map(),
        prim_arrays: new_map(),
        roots: Vec::new(),
        jni_globals: Vec::new(),
    };
    let mut pos = 0usize;
    // The magic is a NUL-terminated string.
    let nul = h.buf[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or("bad hprof: no magic")?;
    let magic = String::from_utf8_lossy(&h.buf[pos..pos + nul]).into_owned();
    pos = nul + 1;
    if !magic.starts_with("JAVA PROFILE") {
        return Err(format!("bad hprof magic: {magic}"));
    }
    h.id_size = h.u32(pos);
    pos += 4 + 8; // idSize + timestamp
    eprintln!(
        "[{:.2}s] hprof={} idSize={} bytes={}",
        t0.elapsed().as_secs_f64(),
        magic,
        h.id_size,
        h.buf.len()
    );

    let id_size = h.id_size as usize;
    let heap_parse = |h: &mut Heap, start: usize, end: usize| -> Result<(), String> {
        let mut pos = start;
        while pos < end {
            let tag = h.buf[pos];
            pos += 1;
            match tag {
                0xFF => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::Unknown,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x01 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    let jref = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::JniGlobal,
                        id,
                        jni_ref: jref,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                    h.jni_globals.push(id);
                }
                0x02 | 0x03 | 0x8E => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    let thread = h.u32(pos);
                    let depth = h.u32(pos + 4);
                    pos += 8;
                    let kind = match tag {
                        0x02 => RootKind::JniLocal,
                        0x03 => RootKind::JavaFrame,
                        _ => RootKind::JniMonitor,
                    };
                    h.roots.push(Root {
                        kind,
                        id,
                        jni_ref: 0,
                        thread,
                        depth,
                        has_thread: true,
                        has_depth: true,
                    });
                }
                0x04 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    let thread = h.u32(pos);
                    pos += 4;
                    h.roots.push(Root {
                        kind: RootKind::NativeStack,
                        id,
                        jni_ref: 0,
                        thread,
                        depth: 0,
                        has_thread: true,
                        has_depth: false,
                    });
                }
                0x05 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::StickyClass,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x06 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    let thread = h.u32(pos);
                    pos += 4;
                    h.roots.push(Root {
                        kind: RootKind::ThreadBlock,
                        id,
                        jni_ref: 0,
                        thread,
                        depth: 0,
                        has_thread: true,
                        has_depth: false,
                    });
                }
                0x07 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::MonitorUsed,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x08 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    let thread = h.u32(pos);
                    pos += 8; // thread + stack trace serial
                    h.roots.push(Root {
                        kind: RootKind::ThreadObject,
                        id,
                        jni_ref: 0,
                        thread,
                        depth: 0,
                        has_thread: true,
                        has_depth: false,
                    });
                }
                0x20 => {
                    // CLASS_DUMP
                    let class_id = h.id_at(pos);
                    pos += id_size + 4; // class id + stack trace serial
                    let super_id = h.id_at(pos);
                    pos += id_size;
                    let loader_id = h.id_at(pos);
                    pos += id_size * 5; // loader_id + signers, protection domain, reserved1, reserved2
                    let instance_size = h.u32(pos);
                    pos += 4;
                    let cp_count = h.u16(pos) as usize;
                    pos += 2;
                    let mut cp_refs = Vec::new();
                    for _ in 0..cp_count {
                        pos += 2; // constant pool index
                        let t = h.buf[pos];
                        pos += 1;
                        if t == 2 {
                            cp_refs.push(h.id_at(pos));
                            pos += id_size;
                        } else {
                            pos += h.type_size(t) as usize;
                        }
                    }
                    let static_count = h.u16(pos) as usize;
                    pos += 2;
                    let mut statics = Vec::new();
                    for _ in 0..static_count {
                        let name_id = h.id_at(pos);
                        pos += id_size;
                        let t = h.buf[pos];
                        pos += 1;
                        if t == 2 {
                            statics.push((name_id, h.id_at(pos)));
                            pos += id_size;
                        } else {
                            pos += h.type_size(t) as usize;
                        }
                    }
                    let field_count = h.u16(pos) as usize;
                    pos += 2;
                    let mut fields = Vec::new();
                    for _ in 0..field_count {
                        let name_id = h.id_at(pos);
                        pos += id_size;
                        let ty = h.buf[pos];
                        pos += 1;
                        fields.push((name_id, ty));
                    }
                    h.classes_order.push(class_id);
                    h.classes.insert(
                        class_id,
                        ClassMeta {
                            name: String::new(),
                            super_id,
                            loader_id,
                            statics,
                            fields,
                            instance_size,
                            cp_refs,
                        },
                    );
                }
                0x21 => {
                    let id = h.id_at(pos);
                    pos += id_size + 4;
                    let class_id = h.id_at(pos);
                    pos += id_size;
                    let len = h.u32(pos);
                    pos += 4;
                    h.objects_order.push(id);
                    h.objects.insert(
                        id,
                        Obj {
                            k: 1,
                            c: class_id,
                            o: pos,
                            n: len,
                        },
                    );
                    pos += len as usize;
                }
                0x22 => {
                    let id = h.id_at(pos);
                    pos += id_size + 4;
                    let count = h.u32(pos);
                    pos += 4;
                    let class_id = h.id_at(pos);
                    pos += id_size;
                    h.objects_order.push(id);
                    h.objects.insert(
                        id,
                        Obj {
                            k: 2,
                            c: class_id,
                            o: pos,
                            n: count,
                        },
                    );
                    pos += count as usize * id_size;
                }
                0x23 => {
                    let id = h.id_at(pos);
                    pos += id_size + 4;
                    let count = h.u32(pos);
                    pos += 4;
                    let ty = h.buf[pos];
                    pos += 1;
                    if ty == 8 {
                        h.byte_arrays.insert(id, (pos, count));
                    }
                    h.prim_arrays.insert(id, (ty, count as u64));
                    pos += count as usize * h.type_size(ty) as usize;
                }
                0xC3 => pos += id_size + 4 + 4 + 1,
                0x89 => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::InternedString,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x8A => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::Finalizing,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x8B => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::Debugger,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x8C => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::ReferenceCleanup,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x8D => {
                    let id = h.id_at(pos);
                    pos += id_size;
                    h.roots.push(Root {
                        kind: RootKind::VmInternal,
                        id,
                        jni_ref: 0,
                        thread: 0,
                        depth: 0,
                        has_thread: false,
                        has_depth: false,
                    });
                }
                0x90 => pos += id_size, // UNREACHABLE: not a strong root, so it is skipped
                0xFE => pos += 4 + id_size, // HEAP_DUMP_INFO
                _ => {
                    return Err(format!(
                        "hprof: unknown heap subrecord 0x{tag:x} at {}",
                        pos - 1
                    ));
                }
            }
        }
        Ok(())
    };

    while pos + 9 <= h.buf.len() {
        let tag = h.buf[pos];
        pos += 1;
        pos += 4; // time
        let len = h.u32(pos) as usize;
        pos += 4;
        let end = (pos + len).min(h.buf.len());
        match tag {
            0x01 => {
                let id = h.id_at(pos);
                pos += id_size;
                h.strings.insert(
                    id,
                    String::from_utf8_lossy(&h.buf[pos..end])
                        .into_owned()
                        .into(),
                );
            }
            0x02 => {
                pos += 4;
                let class_id = h.id_at(pos);
                pos += id_size;
                pos += 4;
                let name_id = h.id_at(pos);
                h.loaded_class.insert(class_id, name_id);
            }
            0x0C | 0x1C => heap_parse(&mut h, pos, end)?,
            _ => {}
        }
        pos = end;
    }

    // Precompute every class name once, keeping the fallback labels the output baseline was built with:
    // a class with no LOAD_CLASS record, or whose name string is missing, still has to print something.
    let names: Vec<(u64, String)> = h
        .classes_order
        .iter()
        .map(|&cid| {
            let name = match h.loaded_class.get(&cid) {
                Some(&sid) => h
                    .strings
                    .get(&sid)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("<string:{sid:x}>")),
                None => format!("<class:{cid:x}>"),
            };
            (cid, name)
        })
        .collect();
    for (cid, name) in names {
        if let Some(m) = h.classes.get_mut(&cid) {
            m.name = name;
        }
    }
    eprintln!(
        "[{:.2}s] parsed strings={} classes={} objects={} roots={}",
        t0.elapsed().as_secs_f64(),
        h.strings.len(),
        h.classes.len(),
        h.objects.len(),
        h.roots.len()
    );
    Ok(h)
}
