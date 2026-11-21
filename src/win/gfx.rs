//! Window enumeration, GDI/GDI+ screen capture, and local-time helpers.

use std::collections::BTreeSet;

use windows::Win32::Foundation::{HWND, LPARAM, RECT, SYSTEMTIME};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleBitmap, CreateCompatibleDC,
    DIB_USAGE, DeleteDC, DeleteObject, GetDC, GetDIBits, HBITMAP, HDC, HGDIOBJ, HPALETTE,
    ReleaseDC, SRCCOPY, SelectObject,
};
use windows::Win32::Graphics::GdiPlus::{
    GdipCreateBitmapFromHBITMAP, GdipDisposeImage, GdipSaveImageToFile, GdiplusShutdown,
    GdiplusStartup, GdiplusStartupInput, GpBitmap, GpImage,
};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowRect, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
    IsIconic, IsWindowVisible,
};
use windows::core::{BOOL, GUID};

/// The PNG encoder CLSID: {557CF406-1A04-11D3-9A73-0000F81EF32E}, from GdiPlusImaging.h.
const CLSID_IMAGE_PNG: GUID = GUID::from_u128(0x557cf406_1a04_11d3_9a73_0000f81ef32e);

pub(crate) struct WinInfo {
    pub(crate) hwnd: HWND,
    pub(crate) pid: u32,
    pub(crate) visible: bool,
    pub(crate) minimized: bool,
    pub(crate) rect: RECT,
    pub(crate) title: String,
}

pub(crate) fn enumerate(match_pids: Option<&BTreeSet<u32>>) -> Vec<WinInfo> {
    struct Ctx<'a> {
        pids: Option<&'a BTreeSet<u32>>,
        out: Vec<WinInfo>,
    }
    unsafe extern "system" fn cb(h: HWND, lparam: LPARAM) -> BOOL {
        // Edition 2024 removes the implicit unsafe body of an unsafe fn, so the block is written out.
        // lparam carries the address of the Ctx built at the EnumWindows call site, which outlives this
        // synchronous callback.
        unsafe {
            let ctx = &mut *(lparam.0 as *mut Ctx);
            let mut pid = 0u32;
            GetWindowThreadProcessId(h, Some(&mut pid));
            if let Some(set) = ctx.pids {
                if !set.contains(&pid) {
                    return true.into();
                }
            }
            let len = GetWindowTextLengthW(h);
            let mut buf = vec![0u16; (len.max(0) + 1) as usize];
            GetWindowTextW(h, &mut buf);
            let mut rect = RECT::default();
            let _ = GetWindowRect(h, &mut rect);
            ctx.out.push(WinInfo {
                hwnd: h,
                pid,
                visible: IsWindowVisible(h).as_bool(),
                minimized: IsIconic(h).as_bool(),
                rect,
                title: String::from_utf16_lossy(&buf[..len.max(0) as usize]),
            });
            true.into()
        }
    }
    let mut ctx = Ctx {
        pids: match_pids,
        out: Vec::new(),
    };
    unsafe {
        let _ = EnumWindows(Some(cb), LPARAM(&mut ctx as *mut _ as isize));
    }
    ctx.out
}

pub(crate) fn now_hms_f() -> String {
    let st: SYSTEMTIME = unsafe { GetLocalTime() };
    format!(
        "{:02}{:02}{:02}{:03}",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds
    )
}

pub(crate) fn now_csv() -> String {
    let st: SYSTEMTIME = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

/// Captures a rectangle with GDI `BitBlt` and writes it as PNG through GDI+. The 32bpp BGRA pixels are
/// read back with `GetDIBits` (top-down) in the same call so the caller can diff frames.
pub(crate) fn grab_png_pixels(rect: &RECT, path: &str) -> Result<Vec<u8>, String> {
    unsafe {
        let w = rect.right - rect.left;
        let h = rect.bottom - rect.top;
        let mut token = 0usize;
        // GdiplusVersion must be 1: the crate's Default is all zeros, which GdiplusStartup rejects.
        let input = GdiplusStartupInput {
            GdiplusVersion: 1,
            DebugEventCallback: 0,
            SuppressBackgroundThread: BOOL(0),
            SuppressExternalCodecs: BOOL(0),
        };
        if GdiplusStartup(&mut token, &input, std::ptr::null_mut()).0 != 0 {
            return Err("GdiplusStartup failed".into());
        }
        let r = (|| -> Result<Vec<u8>, String> {
            let hdc_screen: HDC = GetDC(None);
            if hdc_screen.is_invalid() {
                return Err("GetDC failed".into());
            }
            let r = (|| -> Result<Vec<u8>, String> {
                let mem: HDC = CreateCompatibleDC(Some(hdc_screen));
                if mem.is_invalid() {
                    return Err("CreateCompatibleDC failed".into());
                }
                let bmp: HBITMAP = CreateCompatibleBitmap(hdc_screen, w, h);
                if bmp.is_invalid() {
                    return Err("CreateCompatibleBitmap failed".into());
                }
                let old: HGDIOBJ = SelectObject(mem, HGDIOBJ(bmp.0));
                let err = |m: &str| format!("{m}");
                let mut out: Vec<u8>;
                match BitBlt(
                    mem,
                    0,
                    0,
                    w,
                    h,
                    Some(hdc_screen),
                    rect.left,
                    rect.top,
                    SRCCOPY,
                ) {
                    Ok(()) => {
                        // GetDIBits requires the bitmap not to be selected into a DC, so deselect it first.
                        SelectObject(mem, old);
                        let mut bi = BITMAPINFO {
                            bmiHeader: BITMAPINFOHEADER {
                                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                                biWidth: w,
                                biHeight: -h, // top-down
                                biPlanes: 1,
                                biBitCount: 32,
                                biCompression: BI_RGB.0,
                                biSizeImage: (w.max(0) * h.max(0) * 4) as u32,
                                ..Default::default()
                            },
                            ..Default::default()
                        };
                        out = vec![0u8; (w.max(0) * h.max(0) * 4) as usize];
                        let got = GetDIBits(
                            hdc_screen,
                            bmp,
                            0,
                            h as u32,
                            Some(out.as_mut_ptr() as *mut std::ffi::c_void),
                            &mut bi,
                            DIB_USAGE(0), // BI_RGB
                        );
                        if got == 0 {
                            out.clear();
                        }
                        let mut image: *mut GpBitmap = std::ptr::null_mut();
                        if GdipCreateBitmapFromHBITMAP(
                            bmp,
                            HPALETTE(std::ptr::null_mut()),
                            &mut image,
                        )
                        .0 != 0
                            || image.is_null()
                        {
                            return Err(err("GdipCreateBitmapFromHBITMAP failed"));
                        }
                        let wide: Vec<u16> =
                            path.encode_utf16().chain(std::iter::once(0)).collect();
                        let saved = GdipSaveImageToFile(
                            image as *mut GpImage,
                            windows::core::PCWSTR::from_raw(wide.as_ptr()),
                            &CLSID_IMAGE_PNG,
                            std::ptr::null(),
                        );
                        GdipDisposeImage(image as *mut GpImage);
                        if saved.0 != 0 {
                            return Err(err(&format!("GdipSaveImageToFile failed: {path}")));
                        }
                    }
                    Err(e) => return Err(err(&format!("BitBlt: {e}"))),
                }
                let _ = DeleteObject(HGDIOBJ(bmp.0));
                let _ = DeleteDC(mem);
                Ok(out)
            })();
            ReleaseDC(None, hdc_screen);
            r
        })();
        GdiplusShutdown(token);
        r
    }
}

/// Percentage of pixels that differ between two same-size BGRA buffers.
pub(crate) fn diff_percent(a: &[u8], b: &[u8]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 100.0;
    }
    let px = a.len() / 4;
    let changed = a
        .chunks_exact(4)
        .zip(b.chunks_exact(4))
        .filter(|(x, y)| x != y)
        .count();
    changed as f64 / px as f64 * 100.0
}
