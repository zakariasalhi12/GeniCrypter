mod config;
mod parser;
mod crypter;
mod stub;

// $> evasion --help
// Evasion Program Usage:
//   --encrypt <target-binary>        Encrypt the target binary.
//   --output <output-binary>         Specify the name of the encrypted binary file.
//   --add-size <size-in-mb>          Increase the binary size (e.g., 101 MB).
//   --delay <seconds>                Specify execution delay in seconds (default: 101).
// $> evasion --encrypt target.exe --output obfuscated.exe --add-size 101 --delay 101
// Encryption is successful! Encrypted binary saved as "obfuscated.exe".
// $> obfuscated.exe
// [INFO] ecuExtion delayed by 101 seconds...
// [INFO] Binary decrypted successfully.
// [INFO] Target program executed.


struct Crypter {
    target_binary: String,
    output: String,
    padding: u64,
    delay: u64,
    verbose: bool,
    vm_detection: bool,
}

impl Crypter {
    fn new(target_binary: String, output: String, padding: u64, delay: u64, verbose: bool, vm_detection: bool) -> Crypter {
        Crypter {
            target_binary,
            output,
            padding,
            delay,
            verbose,
            vm_detection,
        }
    }

    fn encrypt(&self)  {
        todo!()
    }

    fn compress(&self) {
        todo!()
    }

    fn add_padding(&self) {
        todo!()
    }
}

fn main() {
    parser::parser();
}
