mod fsmap;
mod hprof;
mod jprobe;
mod minidump;
#[cfg(windows)]
mod win;

use std::process::ExitCode;

fn usage() -> ! {
    print!(
        "oml-diag - OhMyLoader's Diagnostic Toolbox
Environment: OML_DIAG_THREADS=<n>  cap the worker threads used by the heap analyzers (default: all cores)

minidump (locate a hard JVM crash when there is no hs_err file):
  minidump <dump.dmp> [--full]   exception thread, faulting address and its module, crash-thread
                                 stack range (default reads the first 512MB only); --full adds the
                                 module table, the CONTEXT record, and a return-address scan of the
                                 stack

heap dump analysis:
  hprof <dump.hprof> [flags]     shortest strong-reference path from the GC roots to the target
                                 class loaders, plus the JNI / Reference / ClassValue / hidden-class
                                 audits
    --final-refs            follow FinalReference.referent during the BFS
    --hidden                hidden-class (LambdaForm$MH) audit only, then exit
    --hidden-session-roots  seed hidden-class statics as roots as well
    --cp-hook               list classes whose constant pool references a hook class, then continue
    --threads               list all threads
    --quick                 exit after the BFS and its paths
    --classvalue            exit after the ClassValue/Field deep audit
    --target <Class.Name>   add a target class
    --dom [--top N]         retained size from the dominator tree, then exit (full GC-reachable
                            graph: all class statics plus VM roots seeded, raw arrays counted in
                            their holder; default top=30)

two-dump comparison:
  hprof-diff <old.hprof> <new.hprof> [--top N]
                                 per-class instance and array deltas, ranked by |delta| (dump before
                                 and after a soft restart to see what survived)

reference-path analysis to one class (pure Rust, independent graph semantics, cross-checks hprof):
  hprof-soft <dump.hprof> <Target.Class> [extra...]
                                 shortest reference path from the GC roots to instances of the class;
                                 'inspect' adds the first three instances' field values

embedded Java probe (source compiled into this binary; needs JDK 11+ java on PATH):
  reflect-probe                  ReflectProbe: MethodHandle cache fields, ObjectMethods statics,
                                 Unsafe accessors - the JDK's own internal fields, through the
                                 single-file source launcher with --add-opens added

windows / capture / resources (Windows only):
  win      [--filter <s>] [--all] [--out <f>]
                                 enumerate top-level windows (--filter matches a substring of the
                                 process command line, default OMLBootstrap; --all lists everything)
  shot     [--filter <s>] [--out-dir <d>] [--interval-ms <n>] [--duration-sec <n>]
           [--fg]                capture PNG frames with a per-frame pixel diff. Default finds the
                                 largest visible window of the matching processes, brings it forward,
                                 then shoots every interval-ms for duration-sec (defaults: filter=oml,
                                 out-dir=shots, 100ms, 200s); --fg shoots the current foreground window
                                 and writes index.csv instead
  handles  [--filter <s>] [--interval-sec <n>] [--duration-sec <n>] [--out <f>]
                                 sample handle / GDI / USER object counts to CSV (defaults: filter=oml,
                                 5s, 600s, handles.csv)

debug helpers:
  cmdline  [--dump] <pid>        print a process command line through its PEB; on failure --dump
                                 hexdumps the parameters region
  env      <pid> [substr]        print a process environment block through its PEB, optionally
                                 filtered by a substring (case-insensitive)"
    );
    std::process::exit(0);
}

fn usage_err() -> ! {
    eprintln!("error: unknown command or missing args; run `oml-diag --help`");
    std::process::exit(2);
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
    }
    let cmd = args[0].clone();
    let rest = &args[1..];

    let r = match cmd.as_str() {
        "minidump" => {
            let Some(p) = rest.first() else { usage_err() };
            if flag(rest, "--full") {
                minidump::dump_info(p)
            } else {
                minidump::dump_header(p)
            }
        }
        "hprof" => {
            let Some(p) = rest.first() else { usage() };
            let o = &rest[1..];
            let cfg = hprof::Config {
                final_refs: flag(o, "--final-refs"),
                hidden: flag(o, "--hidden"),
                hidden_session_roots: flag(o, "--hidden-session-roots"),
                cp_hook: flag(o, "--cp-hook"),
                threads: flag(o, "--threads"),
                quick: flag(o, "--quick"),
                classvalue: flag(o, "--classvalue"),
                dom: flag(o, "--dom"),
                top: opt(o, "--top")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30usize),
                targets: {
                    let mut v: Vec<String> = Vec::new();
                    let mut i = 0;
                    while i < o.len() {
                        if o[i] == "--target" {
                            if let Some(t) = o.get(i + 1) {
                                v.push(t.replace('.', "/"));
                            }
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    v
                },
            };
            hprof::run(p, &cfg)
        }
        #[cfg(windows)]
        "cmdline" => {
            let Some(p) = rest.first() else { usage_err() };
            match p.parse::<u32>() {
                Ok(pid) => win::cmdline_dbg(pid, flag(rest, "--dump")),
                Err(_) => Err("pid must be a number".to_string()),
            }
        }
        #[cfg(windows)]
        "env" => {
            let Some(p) = rest.first() else { usage_err() };
            match p.parse::<u32>() {
                Ok(pid) => win::env_dbg(pid, rest.get(1).map(|s| s.as_str())),
                Err(_) => Err("pid must be a number".to_string()),
            }
        }
        "hprof-diff" => {
            let (Some(o), Some(n)) = (rest.first(), rest.get(1)) else {
                usage_err()
            };
            let top = opt(rest, "--top")
                .and_then(|s| s.parse().ok())
                .unwrap_or(30usize);
            hprof::diff::run(o, n, top)
        }
        "hprof-soft" => {
            let (Some(d), Some(t)) = (rest.first(), rest.get(1)) else {
                usage_err()
            };
            hprof::soft::run(d, t, &rest[2..])
        }
        "reflect-probe" => jprobe::reflect_probe(),
        #[cfg(windows)]
        "win" => win::win_probe(
            opt(rest, "--filter"),
            flag(rest, "--all"),
            opt(rest, "--out").as_deref(),
        ),
        #[cfg(windows)]
        "shot" => {
            let a = win::ShotArgs {
                filter: opt(rest, "--filter").unwrap_or_else(|| "oml".into()),
                out_dir: opt(rest, "--out-dir").unwrap_or_else(|| "shots".into()),
                interval_ms: opt(rest, "--interval-ms")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(100),
                duration_sec: opt(rest, "--duration-sec")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(200),
            };
            if flag(rest, "--fg") {
                win::foreground_shot(a)
            } else {
                win::window_shot(a)
            }
        }
        #[cfg(windows)]
        "handles" => win::handle_sample(
            opt(rest, "--filter").unwrap_or_else(|| "oml".into()),
            opt(rest, "--interval-sec")
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            opt(rest, "--duration-sec")
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            opt(rest, "--out").unwrap_or_else(|| "handles.csv".into()),
        ),
        _ => usage_err(),
    };

    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
