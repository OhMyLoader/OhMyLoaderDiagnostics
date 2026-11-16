//! Zero-copy file mapping: the map is leaked as a `'static` slice and never unmapped.
//!
//! The process exits when the command is done, so an explicit unmap would only delay it. Mapping also
//! removes a whole-file copy and an equal amount of heap, with pages arriving through the page cache. The
//! file must not change while it is mapped: truncation raises `SIGBUS` or an access violation, so a dump
//! that is still being written is not a valid input.

pub(crate) fn map_file(path: &str) -> Result<&'static [u8], String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let len = f.metadata().map_err(|e| format!("stat {path}: {e}"))?.len();
    if len == 0 {
        return Err(format!("{path}: empty file"));
    }
    let mmap = unsafe { memmap2::Mmap::map(&f) }.map_err(|e| format!("mmap {path}: {e}"))?;
    Ok(&Box::leak(Box::new(mmap))[..])
}
