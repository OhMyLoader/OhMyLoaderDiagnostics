//! Embedded Java probe: `tools/ReflectProbe.java` is compiled into this binary with `include_str!`,
//! written to a temporary directory at run time, and executed as a single-file source program
//! (`java ReflectProbe.java`, JDK 11+) with stdio passed straight through.
//!
//! It has to live in a JVM: it reflects the JDK's own internal fields, which Rust has no equivalent of.
//! `hprof-soft` used to need the same escape hatch and is now pure Rust (see `hprof/soft.rs`).

/// ReflectProbe: JDK-internal fields at run time (`reflect-probe`).
const REFLECT_PROBE: &str = include_str!("../tools/ReflectProbe.java");

/// Writes the embedded source to the temporary directory, overwriting it so it always matches this binary.
fn extract() -> Result<std::path::PathBuf, String> {
    let dir = std::env::temp_dir().join("oml-diag-embed");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let p = dir.join("ReflectProbe.java");
    std::fs::write(&p, REFLECT_PROBE).map_err(|e| format!("write {}: {e}", p.display()))?;
    Ok(p)
}

/// `reflect-probe`: `MethodHandle` cache fields, `ObjectMethods` statics, `Unsafe` accessors.
/// `sun.misc` is in the `jdk.unsupported` module (JDK 9+), so the reflection needs the module boundary
/// opened explicitly.
pub fn reflect_probe() -> Result<(), String> {
    let p = extract()?;
    let args = vec![
        "--add-opens=jdk.unsupported/sun.misc=ALL-UNNAMED".to_string(),
        p.to_string_lossy().into_owned(),
    ];
    let mut cmd = std::process::Command::new("java");
    cmd.args(&args);
    match cmd.status() {
        Ok(st) if st.success() => Ok(()),
        Ok(st) => Err(format!("java exited with {st}")),
        Err(e) => Err(format!(
            "launch java failed: {e} (needs a JDK 11+ java on PATH)"
        )),
    }
}
