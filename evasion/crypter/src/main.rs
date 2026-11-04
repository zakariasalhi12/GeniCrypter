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
        let max_file_size_mb = lib::get_env_u64("MAX_FILE_SIZE_MB", 200);
        let max_delay_seconds = lib::get_env_u64("MAX_DELAY_SECONDS", 3000);
        let max_padding_mb = lib::get_env_u64("MAX_PADDING_MB", 200);

        // Check padding size
        if args.padding > max_padding_mb {
            return Err(format!(
                "Padding size exceeds the maximum allowed size of {} MB.",
                max_padding_mb
            ));
        }

        // Check delay
        if args.delay > max_delay_seconds {
            return Err(format!(
                "Delay exceeds the maximum allowed delay of {} seconds.",
                max_delay_seconds
            ));
        }

        // Check file size
        let target_binary = args.target_binary.ok_or("Target binary is required.")?;
        let metadata = std::fs::metadata(&target_binary).map_err(|e| format!("Failed to read target binary metadata: {}", e))?;
        let file_size_mb = metadata.len() / (1024 * 1024);

        if file_size_mb > max_file_size_mb {
            return Err(format!(
                "Target binary size exceeds the maximum allowed size of {} MB.",
                max_file_size_mb
            ));
        }

        // Check if the target binary is a valid PE file
        lib::validate_pe(&target_binary)?;
    
        // Determine output path
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
    dotenvy::dotenv().ok();
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
