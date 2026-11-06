use colored::Colorize;
use obfstr::obfstr;

pub fn log_ok(msg: &str) {
    println!("{} {}", obfstr!("[+]").green(), msg);
}

pub fn log_info(msg: &str) {
    println!("{} {}", obfstr!("[*]").yellow(), msg);
}

pub fn log_error(msg: &str) {
    println!("{} {}", obfstr!("[-]").red(), msg);
}