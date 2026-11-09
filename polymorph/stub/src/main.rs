use busywork::{BusyWork, Categories, Intensity};

// The provided shellcode
static SHELLCODE: &[u8] = include_bytes!("../shellcode");


fn random_behavior() {
    let worker = Busywork::new(Intensity::High).allow(Categories::all()).run();
}

fn main() {
    println!("Hello, world!");
}