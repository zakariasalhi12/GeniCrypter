mod config;

// $> evasion --help
// Evasion Program Usage:
//   --encrypt <target-binary>        Encrypt the target binary.
//   --output <output-binary>         Specify the name of the encrypted binary file.
//   --add-size <size-in-mb>          Increase the binary size (e.g., 101 MB).
//   --delay <seconds>                Specify execution delay in seconds (default: 101).
// $> evasion --encrypt target.exe --output obfuscated.exe --add-size 101 --delay 101
// Encryption is successful! Encrypted binary saved as "obfuscated.exe".
// $> obfuscated.exe
// [INFO] Execution delayed by 101 seconds...
// [INFO] Binary decrypted successfully.
// [INFO] Target program executed.


fn main() {
    // config::Config::new(target_binary_path, output_path, added_size, delay)
    todo!()
}
