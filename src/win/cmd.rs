//! The user-facing subcommands: win / shot (window and foreground modes) / handles.

use std::collections::BTreeSet;

use windows::Win32::Foundation::{CloseHandle, RECT};
use windows::Win32::System::Threading::{
    GR_GDIOBJECTS, GR_USEROBJECTS, GetProcessHandleCount, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, SW_RESTORE, SetForegroundWindow, ShowWindow,
};

use super::ShotArgs;
use super::gfx::{WinInfo, diff_percent, enumerate, grab_png_pixels, now_csv, now_hms_f};
use super::peb::pids_matching;

/// `win`: enumerate top-level windows, filtered by a substring of the process command line (`--all` for
/// everything).
pub fn win_probe(filter: Option<String>, all: bool, out: Option<&str>) -> Result<(), String> {
    let pids: Option<BTreeSet<u32>> = if all {
        None
    } else {
        let f = filter.unwrap_or_else(|| "OMLBootstrap".into());
        let ids: BTreeSet<u32> = pids_matching(&f).into_iter().map(|(p, _)| p).collect();
        eprintln!(
            "matching pids ({}): {}",
            f,
            ids.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        Some(ids)
    };
    let wins = enumerate(pids.as_ref());
    let lines: Vec<String> = wins
        .iter()
        .map(|w| {
            format!(
                "pid={} vis={} min={} rect={},{},{},{} title='{}'",
                w.pid,
                w.visible,
                w.minimized,
                w.rect.left,
                w.rect.top,
                w.rect.right,
                w.rect.bottom,
                w.title
            )
        })
        .collect();
    if let Some(path) = out {
        std::fs::write(path, lines.join("\n") + "\n").map_err(|e| format!("write {path}: {e}"))?;
    }
    for l in &lines {
        println!("{l}");
    }
    Ok(())
}

/// `shot`: find the largest visible window of the matching processes, bring it forward, then capture PNG
/// frames at the configured interval.
pub fn window_shot(args: ShotArgs) -> Result<(), String> {
    std::fs::create_dir_all(&args.out_dir).map_err(|e| format!("mkdir: {e}"))?;
    let pids: BTreeSet<u32> = pids_matching(&args.filter)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    println!(
        "matching pids: {}",
        pids.iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.duration_sec);
    let mut i = 0u32;
    let mut brought = false;
    let mut prev: Vec<u8> = Vec::new();
    while std::time::Instant::now() < deadline {
        let wins = enumerate(Some(&pids));
        let mut best: Option<&WinInfo> = None;
        let mut best_area = 0i64;
        for w in &wins {
            if !w.visible || w.minimized {
                continue;
            }
            let area =
                ((w.rect.right - w.rect.left) as i64) * ((w.rect.bottom - w.rect.top) as i64);
            if area > best_area {
                best_area = area;
                best = Some(w);
            }
        }
        if let Some(b) = best {
            if !brought {
                unsafe {
                    let _ = ShowWindow(b.hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(b.hwnd);
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
                brought = true;
            }
            let (w, h) = (b.rect.right - b.rect.left, b.rect.bottom - b.rect.top);
            if w > 100 && h > 100 {
                i += 1;
                let path = format!("{}/g{:04}_{}.png", args.out_dir, i, now_hms_f());
                let px = grab_png_pixels(&b.rect, &path)?;
                let changed = if prev.is_empty() {
                    String::new()
                } else {
                    format!(" diff={:.2}%", diff_percent(&prev, &px))
                };
                println!("frame {i} {} {}x{}{changed}", now_hms_f(), w, h);
                prev = px;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
    }
    println!("captured {i} frames into {}", args.out_dir);
    Ok(())
}

/// `shot --fg`: keep capturing whichever window is foreground, recording each frame in index.csv.
pub fn foreground_shot(args: ShotArgs) -> Result<(), String> {
    use std::io::Write;
    std::fs::create_dir_all(&args.out_dir).map_err(|e| format!("mkdir: {e}"))?;
    let csv_path = format!("{}/index.csv", args.out_dir);
    std::fs::write(&csv_path, "file;pid;title;w;h\n").map_err(|e| format!("write csv: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.duration_sec);
    let mut i = 0u32;
    let mut prev: Vec<u8> = Vec::new();
    while std::time::Instant::now() < deadline {
        unsafe {
            let h = GetForegroundWindow();
            if !h.is_invalid() {
                let mut rect = RECT::default();
                let _ = GetWindowRect(h, &mut rect);
                let (w, hh) = (rect.right - rect.left, rect.bottom - rect.top);
                let len = GetWindowTextLengthW(h);
                let mut buf = vec![0u16; (len.max(0) + 1) as usize];
                GetWindowTextW(h, &mut buf);
                let title = String::from_utf16_lossy(&buf[..len.max(0) as usize]);
                let mut pid = 0u32;
                GetWindowThreadProcessId(h, Some(&mut pid));
                if w > 100 && hh > 100 {
                    i += 1;
                    let name = format!("g{:04}_{}.png", i, now_hms_f());
                    let px = grab_png_pixels(&rect, &format!("{}/{}", args.out_dir, name))?;
                    let changed = if prev.len() == px.len() && !px.is_empty() {
                        format!(" diff={:.2}%", diff_percent(&prev, &px))
                    } else {
                        " resized".to_string()
                    };
                    println!("frame {i} {} {}x{} '{title}'{changed}", now_hms_f(), w, hh);
                    prev = px;
                    let mut csv = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&csv_path)
                        .map_err(|e| e.to_string())?;
                    writeln!(csv, "{};{};{};{};{}", name, pid, title, w, hh)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(args.interval_ms));
    }
    println!(
        "captured {i} frames into {} (index: {csv_path})",
        args.out_dir
    );
    Ok(())
}

/// `handles`: sample handle / GDI / USER object counts across restarts into a CSV.
pub fn handle_sample(
    filter: String,
    interval_sec: u64,
    duration_sec: u64,
    out: String,
) -> Result<(), String> {
    std::fs::write(&out, "timestamp;pid;handles;gdi;user\n")
        .map_err(|e| format!("write {out}: {e}"))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(duration_sec);
    let mut n = 0u32;
    use std::io::Write;
    while std::time::Instant::now() < deadline {
        for (pid, _) in pids_matching(&filter) {
            unsafe {
                let h = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                let mut handles = 0u32;
                let _ = GetProcessHandleCount(h, &mut handles);
                let gdi = windows::Win32::System::Threading::GetGuiResources(h, GR_GDIOBJECTS);
                let user = windows::Win32::System::Threading::GetGuiResources(h, GR_USEROBJECTS);
                let _ = CloseHandle(h);
                let line = format!("{};{};{};{};{}", now_csv(), pid, handles, gdi, user);
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(&out)
                    .map_err(|e| e.to_string())?;
                writeln!(f, "{line}").map_err(|e| e.to_string())?;
                println!("{line}");
                n += 1;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(interval_sec));
    }
    println!("sampled {n} rows into {out}");
    Ok(())
}
