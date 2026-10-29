use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "Evasion",
    version,
    about = "A binary crypter with configurable file size and execution delay options.",
    disable_help_flag = true,
    disable_help_subcommand = true
)]
pub struct Args {
    /// Target binary to process
    #[arg(value_name = "target-binary")]
    pub encrypt: Option<PathBuf>,

    /// Output file path
    #[arg(short = 'o', long, value_name = "output-binary", default_value = "result.exe")]
    pub output: PathBuf,

    /// Increase output size in MiB
    #[arg(short = 's', long, value_name = "size-in-mb", default_value_t = 0)]
    pub add_size: u64,

    /// Processing delay in seconds
    #[arg(short = 'd', long, value_name = "seconds", default_value_t = 101)]
    pub delay: u64,
}

pub fn parser() -> Args {
    let args = Args::parse();

    if args.encrypt.is_none() {
        let mut command = Args::command();
        command.print_help().unwrap();
        println!();
        std::process::exit(0);
    }

    args
}