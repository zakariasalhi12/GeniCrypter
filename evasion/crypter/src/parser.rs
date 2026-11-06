use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "Evasion",
    version,
    about = "A Windows binary crypter featuring configurable file size, anti-debugging, virtual machine detection, and execution delay options.",
    disable_help_flag = true,
    disable_help_subcommand = true
)]
pub struct Args {
    // Target binary to process
    #[arg(short = 't', long , value_name = "target-binary")]
    pub target_binary: Option<PathBuf>,

    // Output file path
    #[arg(short = 'o', long, value_name = "output-binary")]
    pub output: Option<PathBuf>,

    // Increase output size in MiB
    #[arg(short = 's', long, value_name = "size-in-mb", default_value_t = 0)]
    pub padding: u64,

    // Processing delay in seconds
    #[arg(short = 'd', long, value_name = "seconds", default_value_t = 60)]
    pub delay: u64,

    // verbose output
    #[arg(short = 'v', long, value_name = "verbose", default_value_t = false)]
    pub verbose: bool,

    // Enable or disable VM detection
    #[arg(short = 'm', long, value_name = "vm-detection", default_value_t = false)]
    pub vm_detection: bool,
}

pub fn parser() -> Result<Args, String> {
    let args = Args::parse();

    if args.target_binary.is_none() {
        let mut command = Args::command();
        command.print_help().map_err(|e| format!("Failed to print help: {}", e))?;
        println!();
        std::process::exit(0);
    }

    Ok(args)
}