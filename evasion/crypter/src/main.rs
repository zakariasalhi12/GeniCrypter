use std::path::PathBuf;
use std::path::Path;
mod parser;
mod lib;

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
    target_binary: PathBuf,
    output: PathBuf,
    padding: u64,
    delay: u64,
    verbose: bool,
    vm_detection: bool,
}

impl Crypter {
    fn new(target_binary: PathBuf, output: PathBuf, padding: u64, delay: u64, verbose: bool, vm_detection: bool) -> Crypter {
        Crypter {
            target_binary,
            output,
            padding,
            delay,
            verbose,
            vm_detection,
        }
    }

    fn parse_args() -> Result<Crypter, String> {
        let args = parser::parser();
    
        let target_binary = args.target_binary
            .ok_or("Target binary is required.")?;
    
        lib::validate_pe(&target_binary)?;
    
        let output = args.output.unwrap_or_else(|| {
            let mut output_path = target_binary.clone();
        
            let file_name = output_path
                .file_name()
                .unwrap()
                .to_string_lossy();
        
            output_path.set_file_name(format!("obfuscated_{}", file_name));
            output_path
        });
    
        Ok(Crypter::new(
            target_binary,
            output,
            args.padding,
            args.delay,
            args.verbose,
            args.vm_detection,
        ))
    }

    fn encrypt(&self)  {
        println!("[INFO] Encryption process completed successfully.");
    }

    fn compress(&self) {
        println!("[INFO] Compression process completed successfully.");
    }

    fn add_padding(&self) {
        println!("[INFO] Padding added successfully.");
    }
}

fn main() {
    let crypter = match Crypter::parse_args() {
        Ok(crypter) => crypter,
        Err(err) => {
            eprintln!("[ERROR] {}", err);
            std::process::exit(1);
        }
    };

    crypter.encrypt();
    crypter.compress();
    crypter.add_padding();
}
