use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "Evasion",
    version,
    about = "A Windows binary crypter featuring configurable persistence, anti-debugging, virtual machine detection, and execution delay options.",
    disable_help_flag = true,
    disable_help_subcommand = true
)]
pub struct Args {
    // Target binary to process
    #[arg(short = 't', long , value_name = "Target binary")]
    pub target_binary: Option<PathBuf>,

    // Output file path
    #[arg(short = 'o', long, value_name = "Output filet")]
    pub output: Option<PathBuf>,

    // Processing delay in seconds
    #[arg(short = 'd', long, value_name = "Process delay in seconds", default_value_t = 60)]
    pub delay: u64,

    // Enable or disable analysis detection
    #[arg(short = 'a', long, default_value_t = false)]
    pub anti_analysis: bool,

    // Enable Persistence
    #[arg(short = 'p', long, default_value_t = false)]
    pub persistence: bool,

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