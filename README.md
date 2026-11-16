# OhMyLoader Diagnostics

`oml-diag` is a single-binary command-line toolbox for reading the artifacts a JVM problem leaves behind:
a minidump from a hard crash, an HPROF heap dump from a leak, and the window, GDI, and process state of a
running Windows machine. The commands were built during the OhMyLoader soft-restart investigation, but the
binary reads no loader state and depends on no loader artifact — any JVM process can be analyzed.

Everything is parsed by hand from the raw bytes: no `dbghelp.dll`, no JVM attach, no WMI. The third-party
dependencies are the Microsoft [`windows` crate](https://crates.io/crates/windows) (Win32 bindings, Windows
targets only) and `memmap2`. `reflect-probe` is the one command that needs a JDK on `PATH`.

## Build

```bash
cargo build --release     # the first build needs network access for the windows crate
./target/release/oml-diag --help
```

Rust edition 2024. `win`, `shot`, `handles`, `cmdline`, and `env` are `#[cfg(windows)]` and are absent from
a Linux build; the heap and crash analyzers are portable. Release profile sets `lto`, `codegen-units=1`,
and `panic = "abort"` — a panic ends the process and discards buffered output, so expected failures are
returned as `Result` and printed by `main`.

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

`OML_DIAG_THREADS=<n>` caps the parallel work in `hprof` and `hprof-soft`; the default is all cores.
Progress and per-stage timings go to stderr, analysis output to stdout, so `> report.txt` stays clean.

## hprof

The default run seeds a multi-source BFS from every VM root and from the statics of every class whose
loader is not one of the targets, then reports the shortest strong-reference path to each
`SessionClassLoader` / `OMLClassLoader` instance and runs twelve leak audits:

```bash
oml-diag hprof dump.hprof
oml-diag hprof dump.hprof --target com.example.MyClassLoader --quick
oml-diag hprof dump.hprof --dom --top 20
```

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

`--top` defaults to 30. The target set is two hard-coded loader class names plus `--target`, so the loader
names are only a default, not a requirement.

A target reported `dist=unreachable` has no strong root path — it is collectable, and a leak somewhere else
is not explained by it. A target with a path printed has that chain as the explanation; each hop shows the
field name that holds the reference, which is what makes the line actionable. `MAX_PREDS` keeps five
predecessors per node, so the enumeration shows up to five shortest paths per target.

`--dom` builds the full GC-reachable graph (all class statics plus all VM roots, raw arrays as leaves whose
bytes count toward their holder) and runs Lengauer-Tarjan semi-NCA for the immediate dominators, then
accumulates retained size bottom-up. CHK iteration was measured on this graph and degrades on its long
dominator chains (one pass over 50 s); LT converges in about 1 s.

### Audit sections

Twelve sections run after the BFS in two parallel groups, and three run only under a flag. Each targets a
reference category that a class loader can be held by without appearing in a short path:

| Section | Checks |
|---|---|
| `jni_global_methodtypes` | JNI global references that are `MethodType` / `MethodHandle` objects |
| `session_references` | `Reference` objects whose referent belongs to the session |
| `persistent_invoke_foreign` | Surviving `invoke` / `foreign` objects |
| `native_libraries` | `NativeLibrary` ownership by a session loader |
| `lwjgl_upcalls` | LWJGL upcall handles still registered |
| `console_statics` | Console and logging statics pointing into the session |
| `classvalue_entries` | `ClassValue` entries keyed by session classes |
| `classvalue_field_deep_audit` | Per-`Field` deep audit of the above |
| `reflection_data_owners` | Soft/Final referents whose owner is a persistent `ReflectionData` |
| `jna_statics` | JNA statics holding session state |
| `lambdaform_reverse_trace` | Reverse trace from `LambdaForm$MH` hidden classes to their owners |
| `shutdown_hooks` | `ApplicationShutdownHooks` entries registered by the session |

Section order is a byte-comparison baseline against the original JavaScript script, including one header
that prints orphaned. Do not reorder `run()` or the section lists to "clean up" output.

## hprof-diff

Aligns two dumps by class name — object ids do not carry across dumps — and ranks the change in instance
counts, object-array counts by element class, `byte[]` and other raw-array counts and bytes by `|delta|`.
The intended use is a soft-restart leak: `jcmd <pid> GC.heap_dump` before and after a restart, then diff the
two files. What survived is the row at the top. Diffing a file against itself prints zeros.

## hprof-soft

A Rust port of the earlier single-file `HprofSoft` tool, byte-identical to it on the `default`,
`not-found`, and `inspect` paths of a real 418 MB dump. It finds the shortest reference path to
**instances of one class** and prints the field name at each hop; the `inspect` argument adds the field
values of the first three instances.

It is deliberately a second implementation rather than a reuse of `hprof`, because the graph semantics
differ: class-node edges include `protectionDomain` and exclude the constant pool; instances and object
arrays carry no `Class` edge; `SoftReference.referent` is kept while other `Reference` subclasses are
skipped; raw arrays are graph nodes; seeding is VM roots plus the class mirrors of live loaders, excluding
mirrors of the session and OML loaders. Two independent reachability conclusions that agree are evidence;
one is a guess. To keep the original output order, the module reimplements `java.util.HashMap` iteration
order (`JavaMap`), which is why the file is long for what it does.

## minidump

For a JVM hard crash that produced no `hs_err` file. The stream directory is parsed directly.

```bash
oml-diag minidump crash.dmp           # header only; maps the first 512 MB
oml-diag minidump crash.dmp --full    # whole file, module table, CONTEXT, stack scan
```

The default view prints the exception thread, the faulting address resolved to `module+0xoffset`, the
access kind and target address for an access violation, and the crash thread's stack range. `--full` adds
the module table, `rip` / `rsp` / `rbp`, and a scan of 8-byte-aligned words near both ends of the crash
thread's stack for values that land inside a known module, i.e. probable return addresses (40 hits per end).

Read it by asking where the faulting address is. An address inside `jvm.dll` is a JVM bug or a bad pointer
into it; `<unmapped>` near an ICD or driver module points to a fault inside the driver — that is how the
Vulkan use-after-destroy was established without symbols.

## win / shot / handles

Windows-side forensics for a soft restart, where the interesting failures are a window that outlives its
process, an overlay that flashes once, and a handle count that never comes back down.

`win` enumerates top-level windows with visibility, minimization, rectangle, and title. The filter matches a
substring of the **process command line** (case-insensitive), resolved through
`NtQueryInformationProcess` → PEB → `RTL_USER_PROCESS_PARAMETERS.CommandLine`; the default filter is
`OMLBootstrap` and `--all` skips matching. System processes have an empty command line and never match, and
your own shell matches if its command line contains the filter.

`shot` captures a window repeatedly. The default mode finds the largest visible window of the matching
processes, restores and foregrounds it once, then writes PNG frames to `--out-dir` every `--interval-ms`
(`--duration-sec` bounds the run). Each frame is read back as BGRA through `GetDIBits` and compared pixel by
pixel with the previous frame, so the printed `diff=` percentages are the timeline of an overlay appearing
and disappearing — you do not have to open the frames to find the moment. `--fg` instead captures whatever
window is foreground at each tick and appends `file;pid;title;w;h` to `index.csv`, for the case where you do
not know which window will show up.

`handles` samples handle, GDI object, and USER object counts per matching pid into a CSV
(`timestamp;pid;handles;gdi;user`). Interpret it phase by phase across several restarts: values flat within
a few dozen mean nothing was left behind; a monotonic rise at the same phase of each cycle is a leak. This is
the measurement that resource residue in `FrontendGpuSurface` was checked with.

`cmdline [--dump] <pid>` and `env <pid> [substr]` are the PEB readers: command line and environment block,
with a hex dump of the parameters region when the read fails, for debugging the offsets themselves.
`env` prefers `ProcessParameters.EnvironmentSize` and falls back to scanning for the double NUL. Use it when
a launch looks polluted (`PATH`, `_JAVA_OPTIONS`).

## reflect-probe

Prints JDK-internal field and method signatures — `MethodHandle` cache fields, `ObjectMethods` statics,
`Unsafe` accessors — before you write a probe or an injection rule against them, so the names are measured
rather than guessed. `tools/ReflectProbe.java` is compiled into the binary with `include_str!`, written to a
temporary directory at run time, and executed as a single-file source program; a JDK 11+ `java` must be on
`PATH`. `sun.misc` lives in the `jdk.unsupported` module, so the launcher adds
`--add-opens=jdk.unsupported/sun.misc=ALL-UNNAMED`.

## Parsing and performance notes

- Dump files are mapped read-only and never unmapped: the map is leaked as a `&'static [u8]` because the
  process exits anyway. This removes a full-file copy and an equal amount of heap; pages arrive through the
  page cache. Truncating a mapped file during a run raises `SIGBUS` / an access violation, so do not analyze
  a dump that is still being written.
- Parsing is a single sequential pass that builds id → record indexes; it is not parallel, and it is the
  floor on the total time.
- BFS node expansion is structural reads only, so a wavefront of up to `1 << 17` nodes is expanded by
  worker threads and then merged serially in FIFO order. `dist` and predecessors therefore match the
  single-threaded result exactly, and output does not depend on thread count.
- Derived expansion data (flattened field chains, `Reference` and `FinalReference` classification) is
  computed once per class before the BFS and shared read-only through `Arc`. Recomputing it per batch per
  thread dominated the expansion stage at 80k classes.
- The twelve audit sections are independent and read-only, so they run in parallel, each buffering its own
  output, flushed in list order — byte-identical to the single-threaded run.
- `u64`-keyed maps use an FxHash-style hasher instead of `RandomState`: about an order of magnitude faster
  on id keys, and deterministic iteration within a build, which the output baseline depends on. Anything
  whose order reaches stdout is sorted explicitly.
- Measured on a 418 MB dump, 32 cores: about 5 s end to end, roughly 1.0 GB peak private commit. `--dom`
  is about 5.3 s.

## Source layout

```
src/
  main.rs            CLI parsing and dispatch only; no analysis logic
  fsmap.rs           read-only mmap that is never unmapped
  minidump.rs        minidump stream-directory parsing
  jprobe.rs          reflect-probe: embedded Java source plus source-file launcher
  hprof/
    mod.rs           Config, run() orchestration, section scheduling
    model.rs         Root / ClassMeta / Obj / Heap and their queries
    parse.rs         HPROF 1.0.2 single-pass parser over the mmap
    hash.rs          FxHash-style hasher and the HashMap alias it shadows
    bfs.rs           wavefront-parallel BFS, path enumeration, formatting
    audit.rs         audit sections (12 scheduled, 3 flag-only)
    diff.rs          two-dump comparison aligned by class name
    dom.rs           Lengauer-Tarjan dominator tree and retained size
    soft.rs          hprof-soft: independent graph semantics for cross-checking
  win/
    mod.rs           ShotArgs and module declarations
    peb.rs           cross-process PEB command line / environment, pid matching
    gfx.rs           window enumeration, GDI/GDI+ capture, BGRA readback
    cmd.rs           win / shot / handles implementations
tools/
  ReflectProbe.java  JDK-internal field probe; the only part that needs java
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the build and verification commands, the output-stability rules,
and the commit and security policy.

## License

AGPL-3.0-or-later, like the other OhMyLoader repositories.
