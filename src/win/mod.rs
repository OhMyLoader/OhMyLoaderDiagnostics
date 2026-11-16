//! Windows-native diagnostics commands: win / shot / handles / cmdline / env.
//!
//! Module split: `peb` (cross-process PEB reads and process matching), `gfx` (window enumeration and
//! GDI/GDI+ capture), `cmd` (the user-facing subcommands).

mod cmd;
mod gfx;
mod peb;

pub use cmd::{foreground_shot, handle_sample, win_probe, window_shot};
pub use peb::{cmdline_dbg, env_dbg};

pub struct ShotArgs {
    pub filter: String,
    pub out_dir: String,
    pub interval_ms: u64,
    pub duration_sec: u64,
}
