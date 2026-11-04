use goblin::Object;
use std::path::Path;
use std::fs;
use sha2::Sha256;
use hkdf::Hkdf;

pub fn validate_pe(path: &Path) -> Result<(), String> {
    
    let buffer = fs::read(path)
        .map_err(|e| format!("Failed to read target file: {}", e))?;

    match Object::parse(&buffer)
        .map_err(|e| format!("Invalid executable: {}", e))?
    {
        Object::PE(_) => Ok(()),
        _ => Err("Only Windows PE executables are accepted.".to_string()),
    }
}

pub fn get_env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(default)
}

pub fn derive_key(passphrase: &[u8], nonce: &[u8; 12]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(nonce), passphrase);
    let mut key = [0u8; 32];
    hk.expand(b"evasion-key", &mut key).expect("hkdf expand");
    key
}