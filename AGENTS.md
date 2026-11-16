# AGENTS.md — OhMyLoader Diagnostics

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. It defines the prerequisites, build and verification
commands, output-stability rules, code style, commit and pull-request rules, security, and licensing. This
file adds only constraints that matter when an agent works in this repository.

- Work only in this repository. It has no loader, plugin, or test-mod dependency, and must keep building
  alone with `cargo`; do not add a cross-repository path or a shared build.
- Do not add a crate to `Cargo.toml` to save a few lines. The dependency set is `memmap2` plus the
  `windows` crate on Windows targets.
- This repository has no test suite. Verify by running the subcommand on a real input and diffing the
  report, and report the command with its output. Do not describe a parser or graph change as verified
  because `cargo build` succeeded.
- Never reorder the audit sections or the calls in `hprof::run`. Buffered output flushed in list order is
  what keeps the parallel run byte-identical to the single-threaded one, and the text is someone's baseline.
- Keep timing and progress on stderr. stdout is the report.
- After any parallelism change, run `OML_DIAG_THREADS=1` and the default and require identical stdout.
- Keep `hprof-soft` a separate implementation with its own graph semantics and its `JavaMap` order
  emulation. Making it call the main BFS looks like a cleanup and removes the cross-check.
- Do not weaken a parse into silence: a malformed dump returns `Err`. Do not add a fallback value that lets
  a truncated file report a plausible-looking answer.
- Keep Windows-only code behind `#[cfg(windows)]` and out of portable modules.
- Do not commit `target/`, heap dumps, minidumps, screenshots, `handles.csv`, or captured reports. Analyzed
  data is never part of a commit.
- Do not mix a `cargo fmt` or `cargo clippy --fix` sweep into a behavioral commit; the tree is not clean at
  either today.
- Commit in this repository. Do not push or tag unless explicitly asked. This repository has no release
  pipeline and no CI.
