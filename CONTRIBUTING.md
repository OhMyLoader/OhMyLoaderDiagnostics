# Contributing to OhMyLoader Diagnostics

This repository builds one Rust binary, `oml-diag`, that analyzes heap dumps, minidumps, and live Windows
process state. It is a standalone tool: it does not depend on the loader, the Gradle plugin, or the test
mod, and it must stay buildable alone with `cargo`.

## Before you start

- Open an issue before changing what a command reports, not just how it computes it. The output text is a
  comparison baseline for people who diff runs across versions.
- Read the "Output stability" section below first. Most of what makes a change here acceptable is in it.
- Do not add a dependency on any OhMyLoader artifact, source path, or Maven coordinate. The loader is one
  of the reasons the tool exists, not part of its build.
- The dependency set is deliberate: `memmap2` plus the `windows` crate on Windows targets. Do not add a
  crate to save a few lines.
- Do not commit analyzed data: heap dumps, minidumps, `shots/`, `handles.csv`, and captured reports stay
  out of the repository.

## Prerequisites

- A Rust toolchain that supports edition 2024 (1.85 or newer; development here uses `1.101.0-nightly`).
- Network access for the first build, which fetches `windows` and `memmap2`; later builds work offline
  with `--offline`.
- Windows for the `win`, `shot`, `handles`, `cmdline`, and `env` code paths. The heap and crash analyzers
  build and run on Linux.
- A JDK 11+ `java` on `PATH` only for `reflect-probe`, which is the single place the tool needs a JVM.
- A real dump to verify against. Sample files are not distributed here; use one from your own incident.

## Build and run

```bash
cargo build --release
cargo build --release --offline        # after the first fetch
./target/release/oml-diag --help

# on Windows
cargo build --release
.\target\release\oml-diag.exe win --filter oml
```

## Verification

There is no automated test suite, so a change is verified by running it and diffing the report:

```bash
# capture before the change, then after it, on the same input
./target/release/oml-diag hprof sample.hprof > before.txt 2> before.err
./target/release/oml-diag hprof sample.hprof > after.txt 2> after.err
diff before.txt after.txt
```

- `hprof`: verify against a dump you have already analyzed with the tool, so a regression has a known
  baseline. Reachability conclusions must not change unless the change is the point, and then the commit
  body says which conclusion moved and why.
- `hprof-diff`: diffing one file against itself must print zero deltas everywhere. That is the invariant
  this subcommand can check without a second sample.
- `hprof-soft`: keep the byte-identical comparison against `hprof` reachability for at least one real dump,
  because that agreement is the tool's whole purpose.
- `minidump`: verify against the same dump before and after; the module+offset lines must be stable.
- `win` / `shot` / `handles`: run against a live process, confirm the CSV headers and the `diff=` field
  did not change, and delete the generated files afterwards.
- Anything touching parallelism: run once with `OML_DIAG_THREADS=1` and once with the default, and require
  stdout to match byte for byte.
- Do not add new `cargo clippy --all-targets` warnings, and do not include a clippy or `cargo fmt` sweep
  in a behavioral commit; format only what you touch, or make the pass its own commit.

Include the commands and their measured output in the pull request. "It compiles" is not evidence for a
parser or a graph change.

## Output stability

These are the rules that protect the tool's usefulness:

- The twelve audit sections run in the order `run()` lists them, and the three flag-only sections print
  where they always have. Buffered output is flushed in list order, which is what makes parallel execution
  byte-identical to the single-threaded run. Do not reorder `GROUP_A`, `GROUP_B`, or the calls in `run()`
  to tidy them; one intentionally orphaned header is part of the historical baseline.
- Timing, progress, and stage counters go to stderr. stdout carries only the report, so `> file` and `diff`
  stay meaningful.
- Any iteration order that reaches stdout must be explicit: sort it, or take it from the Fx-hashed map with
  a fixed insertion order. Never reintroduce `RandomState` for a key whose iteration is observable.
- `hprof-soft` keeps its own graph semantics — `protectionDomain` edges, no constant-pool edges, no
  instance → `Class` edge, `SoftReference.referent` retained, raw arrays as nodes, loader mirrors excluded
  from seeds — and its `JavaMap` iteration-order emulation. Unifying it with the main BFS would remove the
  cross-check, so it is not a refactor that is wanted.
- Parsed input is mapped and never unmapped. Do not add a copy of the file, and do not add a `Drop`-based
  unmap: the `'static` slice is what the analysis code is written against.
- A malformed or truncated dump must surface as an `Err` from the parser — never an index panic and never a
  fallback value. `panic = "abort"` means a panic flushes no output at all.
- Binary-format constants keep their cited field: a PEB or `CONTEXT` offset, an HPROF tag, a `SYSTEMTIME`
  layout gets the name and the format it comes from rather than a bare number at the call site.

## Code style

- Comments and documentation are American English in plain technical style. A comment states a constraint
  the code cannot express: a format rule, an offset, an algorithm choice and the measurement behind it, or
  the output contract that a change would break.
- Do not write investigation history or incident narrative into comments. The reasoning that produced a
  constant belongs in the commit that introduced it.
- Keep `main.rs` to argument parsing and dispatch. New analysis code goes in the module that owns its
  format (`hprof/`, `win/`, `minidump.rs`), not in the dispatcher.
- Windows-specific code stays behind `#[cfg(windows)]`; portable analysis code must not call Win32 APIs.
- `unsafe` blocks keep the invariant that makes them sound on the line above them: what the pointer points
  to, how long it lives, and who else touches it.
- `TODO`, `FIXME`, and `#[deprecated]` have a zero baseline. Do not introduce them.
- `edition = "2024"` and the release profile (`lto`, `codegen-units = 1`, `panic = "abort"`, `strip`) are
  deliberate; changing one needs a measurement, not a preference.

## Commit and pull request

- Branch from `main`; do not commit to upstream `main` directly.
- Use Conventional Commits with the subcommand or module as the scope, for example
  `fix(hprof): count raw arrays in retained size` or `feat(win): add --rect filter`. One concern per commit.
- The body states the constraint and the measured evidence: the input analyzed, the command, and what
  changed in the output. For a performance claim, give the dump size, core count, and before/after timing
  from stderr.
- Update the README section for the subcommand in the same commit when its flags, defaults, or interpretation
  change.
- Do not commit `target/`, dumps, screenshots, CSVs, or local paths.

## Security

Report vulnerabilities privately; the organization-wide policy lives in the
[`.github` repository](https://github.com/OhMyLoader/.github/blob/main/SECURITY.md) and applies here.

A heap dump, a minidump, and a live process's memory are all untrusted inputs to this tool. A malformed
file that aborts the process, or a read that runs past a mapped region, is a defect worth fixing — a
crafted dump is a real attack surface for anyone who runs the tool on files from elsewhere. Do not open
a public issue for it.

## License

The project is licensed under AGPL-3.0-or-later.
