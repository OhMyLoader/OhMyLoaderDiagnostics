//! Minidump parsing from the stream directory alone: no `dbghelp.dll` and no symbol files.

use std::fmt::Write as _;

const STREAM_THREAD_LIST: u32 = 3;
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_EXCEPTION: u32 = 6;

struct Buf {
    data: &'static [u8],
}

impl Buf {
    fn len(&self) -> usize {
        self.data.len()
    }
    fn u32(&self, o: usize) -> u32 {
        u32::from_le_bytes(self.data[o..o + 4].try_into().unwrap())
    }
    fn u64(&self, o: usize) -> u64 {
        u64::from_le_bytes(self.data[o..o + 8].try_into().unwrap())
    }
    /// `MINIDUMP_STRING`: u32 byte length followed by UTF-16LE.
    fn string(&self, rva: u32) -> String {
        let o = rva as usize;
        if o + 4 > self.len() {
            return format!("<bad-rva:{rva:x}>");
        }
        let len = self.u32(o) as usize;
        if o + 4 + len > self.len() {
            return format!("<bad-len:{rva:x}>");
        }
        let u16s: Vec<u16> = self.data[o + 4..o + 4 + len]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    }
    fn stream(&self, num: u32) -> Option<(usize, usize)> {
        if self.u32(0) != 0x504d444d {
            return None; // 'MDMP' magic
        }
        let n = self.u32(8) as usize;
        let dir_rva = self.u32(12) as usize;
        for i in 0..n {
            // A MINIDUMP_DIRECTORY entry is 12 bytes: StreamType + DataSize + Rva.
            let e = dir_rva + i * 12;
            if e + 12 > self.len() {
                return None;
            }
            if self.u32(e) == num {
                let size = self.u32(e + 4) as usize;
                let rva = self.u32(e + 8) as usize;
                return Some((rva, size));
            }
        }
        None
    }
}

struct Module {
    base: u64,
    size: u32,
    name: String,
}

fn modules(b: &Buf) -> Vec<Module> {
    let mut out = Vec::new();
    let Some((off, _)) = b.stream(STREAM_MODULE_LIST) else {
        return out;
    };
    let n = b.u32(off);
    for i in 0..n {
        let m = off + 4 + (i as usize) * 108;
        let base = b.u64(m);
        let size = b.u32(m + 8);
        let name = b.string(b.u32(m + 20));
        if size != 0 {
            out.push(Module { base, size, name });
        }
    }
    out
}

fn where_in(mods: &[Module], addr: u64) -> String {
    for m in mods {
        if addr >= m.base && addr < m.base + m.size as u64 {
            return format!("{}+0x{:x}", m.name, addr - m.base);
        }
    }
    "<unmapped>".to_string()
}

/// The first `cap` bytes only: a slice of the mmap, so still no copy.
fn read_capped(path: &str, cap: usize) -> Result<Buf, String> {
    let data = crate::fsmap::map_file(path)?;
    Ok(Buf {
        data: &data[..data.len().min(cap)],
    })
}

fn read_full(path: &str) -> Result<Buf, String> {
    Ok(Buf {
        data: crate::fsmap::map_file(path)?,
    })
}

/// Crash summary: exception thread, where the faulting address lands, and the crash thread's stack range.
/// Maps the first 512MB only, which is enough for the directory and the exception record.
pub fn dump_header(path: &str) -> Result<(), String> {
    let b = read_capped(path, 512 * 1024 * 1024)?;
    println!(
        "loaded={} file={}",
        b.len(),
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    );

    let mut fault_thread = 0u32;
    let mut ex_addr = 0u64;
    if let Some((eoff, _)) = b.stream(STREAM_EXCEPTION) {
        fault_thread = b.u32(eoff);
        ex_addr = b.u64(eoff + 24);
        let nparams = b.u32(eoff + 32);
        let kind = if nparams >= 2 { b.u64(eoff + 40) } else { 0 };
        let access_addr = if nparams >= 2 { b.u64(eoff + 48) } else { 0 };
        println!(
            "exception thread={fault_thread} 0x{fault_thread:x} addr=0x{ex_addr:x} info={nparams} kind={kind} accessAddr=0x{access_addr:x}"
        );
    } else {
        println!("no exception");
    }

    if let Some((toff, _)) = b.stream(STREAM_THREAD_LIST) {
        let n = b.u32(toff);
        println!("threads={n}");
        for i in 0..n {
            let t = toff + 4 + (i as usize) * 48;
            let tid = b.u32(t);
            if tid == fault_thread {
                let start = b.u64(t + 24);
                let size = b.u32(t + 32);
                let rva = b.u32(t + 36);
                println!("FAULT tid={tid} stack=0x{start:x} size=0x{size:x} rva=0x{rva:x}");
            }
        }
    } else {
        println!("no thread list");
    }

    if let Some((moff, _)) = b.stream(STREAM_MODULE_LIST) {
        let n = b.u32(moff);
        for i in 0..n {
            let m = moff + 4 + (i as usize) * 108;
            let base = b.u64(m);
            let size = b.u32(m + 8) as u64;
            if ex_addr >= base && ex_addr < base + size {
                println!(
                    "exception module 0x{base:x}-0x{:x} {} off=0x{:x}",
                    base + size,
                    b.string(b.u32(m + 20)),
                    ex_addr - base
                );
            }
        }
    }
    Ok(())
}

/// Full view: module table, exception detail, the crash thread's CONTEXT, and a stack return-address scan.
pub fn dump_info(path: &str) -> Result<(), String> {
    let b = read_full(path)?;
    let mods = modules(&b);
    println!("modules={}", mods.len());

    let mut fault_thread = 0u32;
    if let Some((eoff, _)) = b.stream(STREAM_EXCEPTION) {
        fault_thread = b.u32(eoff);
        let code = b.u32(eoff + 8);
        let addr = b.u64(eoff + 24);
        let nparams = b.u32(eoff + 32);
        let mut access_kind = "?".to_string();
        let mut access_addr = 0u64;
        if nparams >= 2 {
            let kind = b.u64(eoff + 40);
            access_addr = b.u64(eoff + 48);
            access_kind = match kind {
                0 => "read".into(),
                1 => "write".into(),
                8 => "execute".into(),
                k => format!("kind={k}"),
            };
        }
        println!(
            "exception thread={fault_thread} code=0x{code:x} address=0x{addr:x} ({})",
            where_in(&mods, addr)
        );
        println!(
            "access={access_kind} address=0x{access_addr:x} ({})",
            where_in(&mods, access_addr)
        );
    } else {
        println!("no exception stream");
    }

    let mut stack_rva = 0u32;
    let mut stack_size = 0u32;
    if let Some((toff, _)) = b.stream(STREAM_THREAD_LIST) {
        let n = b.u32(toff);
        println!("threads={n}");
        for i in 0..n {
            let t = toff + 4 + (i as usize) * 48;
            let tid = b.u32(t);
            if tid != fault_thread {
                continue;
            }
            let start = b.u64(t + 24);
            let dsize = b.u32(t + 32);
            let drva = b.u32(t + 36);
            println!(
                "fault thread stack start=0x{start:x} size=0x{dsize:x} end=0x{:x} rva=0x{drva:x}",
                start + dsize as u64
            );
            // AMD64 CONTEXT: Rip at +248, Rsp at +152, Rbp at +160.
            let crva = b.u32(t + 44) as usize;
            if crva + 256 <= b.len() {
                let rip = b.u64(crva + 248);
                let rsp = b.u64(crva + 152);
                let rbp = b.u64(crva + 160);
                println!(
                    "context flags=0x{:x} rip=0x{rip:x} rsp=0x{rsp:x} rbp=0x{rbp:x}",
                    b.u32(crva + 48)
                );
                println!(
                    "rsp-below-stack={} rsp-above-end={}",
                    rsp < start,
                    rsp >= start + dsize as u64
                );
            }
            stack_rva = drva;
            stack_size = dsize;
            break;
        }
    }

    // Scan the crash thread's stack for 8-byte-aligned words that fall inside a known module: probable
    // return addresses, with the module they belong to.
    if stack_rva != 0 && stack_size != 0 {
        let base_off = stack_rva as usize;
        let max = (stack_size as usize).min(4096);
        let mut seen = 0;
        let mut p = 0usize;
        while p + 8 <= max {
            let v = b.u64(base_off + p);
            if v >= 0x10000 {
                let w = where_in(&mods, v);
                if w != "<unmapped>" {
                    println!("stack-low+0x{p:x}: 0x{v:x} {w}");
                    seen += 1;
                    if seen >= 40 {
                        break;
                    }
                }
            }
            p += 8;
        }
        // The high end of the stack holds the thread entry point and its native caller.
        let mut seen = 0;
        let size = stack_size as usize;
        let mut p = size.saturating_sub(8);
        let floor = size.saturating_sub(8192);
        while p >= floor {
            let v = b.u64(base_off + p);
            if v >= 0x10000 {
                let w = where_in(&mods, v);
                if w != "<unmapped>" {
                    println!("stack-high-0x{:x}: 0x{v:x} {w}", size - p);
                    seen += 1;
                    if seen >= 40 {
                        break;
                    }
                }
            }
            if p < 8 {
                break;
            }
            p -= 8;
        }
    }

    let mut out = String::new();
    for m in &mods {
        let _ = writeln!(
            out,
            "module 0x{:x}-0x{:x} {}",
            m.base,
            m.base + m.size as u64,
            m.name
        );
    }
    print!("{out}");
    Ok(())
}
