use colored::Colorize;

// pub fn log_ok(msg: &str) {
//     println!("{} {}", obfstr!("[+]").green(), msg);
// }

pub fn log_info(msg: &str) {
    println!("{} {}", "[*]".yellow(), msg);
}

pub fn log_error(msg: &str) {
    println!("{} {}", "[-]".red(), msg);
}