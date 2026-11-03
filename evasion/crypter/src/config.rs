use crate::parser::{parser, Args};

pub enum System {
    WINDOWS,
    LINUX,
    MACOS,
    UNKNOWN
}

pub struct Config {
    target_binary_path: String,
    output: String,
    padding: u64,
    delay: u64,
    system: System,
}

impl Config {
    pub fn new(target_binary_path: String, output: String, padding: u64, delay: u64) -> Config {
        Config {
            target_binary_path,
            output,
            padding,
            delay,
            system: System::UNKNOWN 
        }
    }
}
