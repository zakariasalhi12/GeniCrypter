use goblin::Object;
use std::path::Path;
use std::fs;

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