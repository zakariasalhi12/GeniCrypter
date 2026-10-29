use crate::parser::{parser, Args};

pub enum System {
    WINDOWS,
    LINUX,
    MACOS,
    UNKNOWN
}

pub struct Config {
    target_binary_path: String,
    output_path: String,
    added_size: u32,
    delay: u32,
    system: System,
}

impl Config {
    pub fn new(target_binary_path: String, output_path: String, added_size: u32, delay: u32) -> Config {
        Config {
            target_binary_path,
            output_path,
            added_size,
            delay,
            system: System::UNKNOWN 
        }
    }
}
