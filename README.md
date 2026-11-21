# OhMyLoader Diagnostics

`oml-diag` is a single-binary command-line toolbox for reading the artifacts a JVM problem leaves behind:
a minidump from a hard crash, an HPROF heap dump from a leak, and the window, GDI, and process state of a
running Windows machine. The commands were built during the OhMyLoader soft-restart investigation, but the
binary reads no loader state and depends on no loader artifact — any JVM process can be analyzed.
Everything is parsed by hand from the raw bytes: no `dbghelp.dll`, no JVM attach, no WMI.

## Build

```bash
cargo build --release     # the first build needs network access for the windows crate
./target/release/oml-diag --help
```

`win`, `shot`, `handles`, `cmdline`, and `env` are `#[cfg(windows)]` and are absent from a Linux build;
the heap and crash analyzers are portable. Progress and per-stage timings go to stderr, analysis output
to stdout, so `> report.txt` stays clean. `OML_DIAG_THREADS=<n>` caps the parallel work in `hprof` and
`hprof-soft`; the default is all cores.

## Commands

| Command | Input | Purpose |
|---|---|---|
| `minidump <dump.dmp> [--full]` | Windows minidump | Exception thread, faulting address and its module, crash-thread stack scan |
| `hprof <dump.hprof> [flags]` | HPROF 1.0.2 heap dump | Shortest strong-reference path from GC roots to a class loader, plus leak audits |
| `hprof-diff <old> <new> [--top N]` | Two heap dumps | Per-class instance and array growth between the two |
| `hprof-soft <dump> <Class> [inspect]` | HPROF heap dump | Shortest reference path to instances of one class, independent graph semantics |
| `reflect-probe` | none (needs `java`) | JDK-internal field names: `MethodHandle` cache, `ObjectMethods`, `Unsafe` accessors |
| `win [--filter <s>] [--all] [--out <f>]` | live Windows processes | Top-level window state, filtered by process command line |
| `shot [...] [--fg]` | one window | Burst PNG capture with per-frame pixel diff |
| `handles [...]` | live Windows processes | Handle / GDI / USER object counts over time, as CSV |
| `cmdline [--dump] <pid>` | one process | Process command line read from its PEB |
| `env <pid> [substr]` | one process | Process environment block read from its PEB |

## hprof

The default run reports the shortest strong-reference path from GC roots to each
`SessionClassLoader` / `OMLClassLoader` instance — each hop names the field that holds the reference —
and then runs twelve leak audits targeting the reference categories that hold a loader without
appearing in a short path.

| Flag | Effect |
|---|---|
| `--final-refs` | Follow `FinalReference.referent` during the BFS (skipped by default) |
| `--hidden` | Hidden-class (`LambdaForm$MH`) audit only; exits before the BFS |
| `--hidden-session-roots` | Also seed hidden-class statics as roots |
| `--cp-hook` | List classes whose constant pool references a hook class; does not exit |
| `--threads` | List all threads; does not exit |
| `--quick` | Stop after the BFS and its paths |
| `--classvalue` | Stop after the `ClassValue` / `Field` deep audit |
| `--target <Class.Name>` | Add a target class (dots accepted, matched as internal names) |
| `--dom [--top N]` | Retained size from a dominator tree instead of the BFS; exits |

`--top` defaults to 30. The target set is two hard-coded loader class names plus `--target`, so the
loader names are only a default, not a requirement. A target reported `dist=unreachable` has no strong
root path — it is collectable, and the leak is somewhere else. `--dom` builds the full GC-reachable
graph and accumulates retained size from the immediate dominators.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build and verification commands, the output-stability rules,
and the commit and security policy.

## License

AGPL-3.0-or-later, like the other OhMyLoader repositories.
