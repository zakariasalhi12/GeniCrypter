use goblin::Object;
use std::path::Path;
use std::fs;
use colored::Colorize;

pub fn validate_pe(path: &Path) -> Result<(), String> {
    let buffer = fs::read(path).map_err(|e| format!("Failed to read target file: {}", e))?;
    match Object::parse(&buffer).map_err(|e| format!("Invalid executable: {}", e))?
    {
        Object::PE(_) => Ok(()),
        _ => Err("Only Windows PE executables are accepted.".to_string()),
    }
}

pub fn get_env_u64(key: &str, default: u64) -> Result<u64, String> {
    Ok(std::env::var(key).ok().and_then(|value| value.parse::<u64>().ok()).unwrap_or(default))
}

pub fn log_ok(msg: &str) {
    println!("{} {}", "[+]".green(), msg);
}

pub fn log_info(msg: &str) {
    println!("{} {}", "[*]".yellow(), msg);
}

pub fn log_error(msg: &str) {
    println!("{} {}", "[-]".red(), msg);
}