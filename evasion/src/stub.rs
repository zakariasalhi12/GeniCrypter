use std::{env::{Args, args}, os};

pub struct Stub  {
    encrepted_exe : String,
    output : String,
    delay : u32,
    padding: u32,
    key : String
}

impl Stub {
    pub fn new(encrepted_exe : String , output : String, delay : u32 ,padding : u32 , key: String) -> Stub {
        Stub {
            encrepted_exe,
            output,
            delay,
            padding,
            key
        }
    }
    pub fn decrypt(stub: &Stub) {
        todo!()
    }

    pub fn execute(stub: &Stub) {
        todo!()
    }

    pub fn delay_execution(stub: &Stub) {
        todo!()
    }
}

fn main() {

    let args: Vec<String> = args().collect();

    if (args.len() < 6) {
        println!("Invalid number of arguments");
        std::process::exit(1);
    }

    let stub = Stub::new(
        args.get(1).cloned().unwrap_or_else(|| String::from("encrypted.exe")),
        args.get(2).cloned().unwrap_or_else(|| String::from("output.exe")),
        args.get(3).and_then(|s| s.parse::<u32>().ok()).unwrap_or(101),
        args.get(4).and_then(|s| s.parse::<u32>().ok()).unwrap_or(101),
        args.get(5).cloned().unwrap_or_else(|| String::from("encryption_key"))  
    );

    Stub::delay_execution(&stub);
    Stub::decrypt(&stub);
    Stub::execute(&stub);

    std::process::exit(1);
}