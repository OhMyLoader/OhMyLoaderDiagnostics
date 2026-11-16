//! Cross-process reads: PEB → `RTL_USER_PROCESS_PARAMETERS.CommandLine`, and pid matching by command-line
//! substring without WMI.

use std::ffi::c_void;

use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::K32EnumProcesses;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// A command line reaches hundreds of KB for `pwsh -EncodedCommand` and similar, so the cap is 1MB.
const MAX_CMDLINE_BYTES: usize = 1024 * 1024;

pub(crate) fn process_cmdline_dbg(pid: u32) -> Result<String, String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|_| "OpenProcess failed".to_string())?;
        let r = (|| {
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let st = NtQueryInformationProcess(
                h,
                PROCESSINFOCLASS(0), // ProcessBasicInformation
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            );
            if st != NTSTATUS(0) {
                return Err(format!("NtQueryInformationProcess failed (0x{:x})", st.0));
            }
            let peb = pbi.PebBaseAddress as usize;
            if peb == 0 {
                return Err("PebBaseAddress is null".into());
            }
            let params = read_remote_usize(h, peb + 0x20)
                .filter(|v| *v != 0)
                .ok_or_else(|| "read PEB.ProcessParameters failed".to_string())?;
            // UNICODE_STRING (x64, 16 bytes): +0x00 Length(u16), +0x02 MaximumLength, +0x08 Buffer.
            // RTL_USER_PROCESS_PARAMETERS.CommandLine is at params + 0x70.
            let mut us = [0u8; 16];
            ReadProcessMemory(
                h,
                (params + 0x70) as *const c_void,
                us.as_mut_ptr() as *mut c_void,
                16,
                None,
            )
            .map_err(|_| "read CommandLine UNICODE_STRING failed".to_string())?;
            let len = u16::from_le_bytes([us[0], us[1]]) as usize;
            let bufptr = usize::from_le_bytes(us[8..16].try_into().unwrap());
            if len == 0 || bufptr == 0 || len > MAX_CMDLINE_BYTES {
                return Err(format!("bad UNICODE_STRING len={len} buf=0x{bufptr:x}"));
            }
            let mut u16s = vec![0u16; len / 2];
            ReadProcessMemory(
                h,
                bufptr as *const c_void,
                u16s.as_mut_ptr() as *mut c_void,
                len,
                None,
            )
            .map_err(|_| "read command line buffer failed".to_string())?;
            Ok(String::from_utf16_lossy(&u16s))
        })();
        let _ = CloseHandle(h);
        r
    }
}

fn read_remote_usize(h: HANDLE, addr: usize) -> Option<usize> {
    unsafe {
        let mut v = 0usize;
        ReadProcessMemory(
            h,
            addr as *const c_void,
            &mut v as *mut usize as *mut c_void,
            8,
            None,
        )
        .ok()?;
        Some(v)
    }
}

fn process_cmdline(pid: u32) -> Option<String> {
    process_cmdline_dbg(pid).ok()
}

/// Every pid whose command line contains `filter`, case-insensitively, with the command line itself.
pub(crate) fn pids_matching(filter: &str) -> Vec<(u32, String)> {
    let mut ids = vec![0u32; 8192];
    let mut needed = 0u32;
    let mut out = Vec::new();
    unsafe {
        if !K32EnumProcesses(ids.as_mut_ptr(), (ids.len() * 4) as u32, &mut needed).as_bool() {
            return out;
        }
    }
    let n = (needed as usize / 4).min(ids.len());
    let f = filter.to_lowercase();
    for &pid in &ids[..n] {
        if pid == 0 {
            continue;
        }
        if let Some(cmd) = process_cmdline(pid) {
            if cmd.to_lowercase().contains(&f) {
                out.push((pid, cmd));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Prints one pid's command line (for debugging the PEB read). `--dump` adds a hexdump of the parameters
/// region when the read fails.
pub fn cmdline_dbg(pid: u32, hexdump: bool) -> Result<(), String> {
    match process_cmdline_dbg(pid) {
        Ok(c) => {
            println!("{c}");
            Ok(())
        }
        Err(e) if hexdump => {
            println!("pid {pid}: {e}");
            dump_params(pid)
        }
        Err(e) => Err(format!("pid {pid}: {e}")),
    }
}

/// Environment-block read cap: tens of KB for a typical process, but a Java process with several
/// `*_OPTIONS` variables can reach hundreds of KB, so the defensive ceiling is 4MB.
const MAX_ENV_BYTES: usize = 4 * 1024 * 1024;

/// Reads one pid's environment block (PEB.ProcessParameters.Environment, UTF-16, double-NUL terminated)
/// and prints the `KEY=VALUE` lines. `ProcessParameters.EnvironmentSize` (x64, +0x3F0) is preferred; when
/// it cannot be read the block is scanned until the double NUL or the cap.
pub fn env_dbg(pid: u32, filter: Option<&str>) -> Result<(), String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|_| "OpenProcess failed".to_string())?;
        let r = (|| -> Result<(), String> {
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            if NtQueryInformationProcess(
                h,
                PROCESSINFOCLASS(0),
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            ) != NTSTATUS(0)
            {
                return Err("NtQueryInformationProcess failed".into());
            }
            let peb = pbi.PebBaseAddress as usize;
            let params = read_remote_usize(h, peb + 0x20)
                .filter(|v| *v != 0)
                .ok_or_else(|| "read PEB.ProcessParameters failed".to_string())?;
            // RTL_USER_PROCESS_PARAMETERS (x64): Environment at +0x80,
            // EnvironmentSize at +0x3F0 (Win8+).
            let env_ptr = read_remote_usize(h, params + 0x80)
                .filter(|v| *v != 0)
                .ok_or_else(|| "read ProcessParameters.Environment failed".to_string())?;
            let env_size = read_remote_usize(h, params + 0x3F0).unwrap_or(0);
            let mut u16s: Vec<u16> = Vec::new();
            if env_size > 0 && env_size <= MAX_ENV_BYTES {
                let mut buf = vec![0u8; env_size];
                ReadProcessMemory(
                    h,
                    env_ptr as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    env_size,
                    None,
                )
                .map_err(|_| "read environment block failed".to_string())?;
                u16s = buf
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
            } else {
                // No EnvironmentSize field or an implausible value: read in 64KB blocks until the double NUL.
                let chunk = 64 * 1024;
                for _ in 0..(MAX_ENV_BYTES / chunk) {
                    let off = u16s.len();
                    let mut buf = vec![0u8; chunk];
                    if ReadProcessMemory(
                        h,
                        (env_ptr + off * 2) as *const c_void,
                        buf.as_mut_ptr() as *mut c_void,
                        chunk,
                        None,
                    )
                    .is_err()
                    {
                        break; // an unmapped page past the end of the block
                    }
                    u16s.extend(
                        buf.chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]])),
                    );
                    // Two consecutive zero code units end the environment block.
                    if u16s.windows(2).any(|w| w == [0, 0]) {
                        break;
                    }
                }
            }
            let total = u16s.len();
            // Split on NUL; the trailing terminators drop out as empty parts.
            let mut lines = Vec::new();
            for part in u16s.split(|&c| c == 0) {
                if part.is_empty() {
                    continue;
                }
                let s = String::from_utf16_lossy(part);
                if let Some(f) = filter {
                    if !s.to_lowercase().contains(&f.to_lowercase()) {
                        continue;
                    }
                }
                lines.push(s);
            }
            println!("pid={pid} env_bytes={} vars={}", total * 2, lines.len());
            for l in lines {
                println!("{l}");
            }
            Ok(())
        })();
        let _ = CloseHandle(h);
        r
    }
}

fn dump_params(pid: u32) -> Result<(), String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|_| "OpenProcess failed".to_string())?;
        let r = (|| -> Result<(), String> {
            let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            if NtQueryInformationProcess(
                h,
                PROCESSINFOCLASS(0),
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            ) != NTSTATUS(0)
            {
                return Err("NtQueryInformationProcess failed".into());
            }
            let mut params = 0usize;
            ReadProcessMemory(
                h,
                (pbi.PebBaseAddress as usize + 0x20) as *const c_void,
                &mut params as *mut usize as *mut c_void,
                8,
                None,
            )
            .map_err(|_| "read ProcessParameters failed".to_string())?;
            let mut buf = [0u8; 0x90];
            ReadProcessMemory(
                h,
                params as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                None,
            )
            .map_err(|_| "read params region failed".to_string())?;
            for row in 0..buf.len() / 16 {
                let hex: Vec<String> = buf[row * 16..row * 16 + 16]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!("  +{:02x}  {}", row * 16, hex.join(" "));
            }
            Ok(())
        })();
        let _ = CloseHandle(h);
        r
    }
}
