use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "Polymorph",
    version,
    about = "A Windows binary polymorphism tool.",
    disable_help_flag = true,
    disable_help_subcommand = true
)]
pub struct Args {
    // Output file path
    #[arg(short = 'o', long , value_name = "output-binary")]
    pub output: Option<PathBuf>,
    
    // Reverse shell payload file path
    #[arg(short = 'p', long, value_name = "payload")]
    pub payload: Option<PathBuf>,
}

pub fn parser() -> Result<Args, String> {
    let args = Args::parse();

    if args.payload.is_none() {
        let mut command = Args::command();
        command.print_help().map_err(|e| format!("Failed to print help: {}", e))?;
        println!();
        std::process::exit(0);
    }

    Ok(args)
}