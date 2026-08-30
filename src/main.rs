use std::process::ExitCode;

use execwake::cli::{help_text, Cli, Command, HelpTopic, ParseResult};

fn main() -> ExitCode {
    let result = match Cli::parse_env() {
        Ok(result) => result,
        Err(error) => {
            eprintln!("error: {error}\n\n{}", help_text(HelpTopic::Root));
            return ExitCode::from(2);
        }
    };

    let cli = match result {
        ParseResult::Command(cli) => cli,
        ParseResult::Help(topic) => {
            print!("{}", help_text(topic));
            return ExitCode::SUCCESS;
        }
        ParseResult::Version => {
            println!("execwake {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
    };

    match cli.command {
        Command::Run(_) => eprintln!("command tracing is not available yet"),
        Command::Diff(_) => eprintln!("session comparison is not available yet"),
    }

    ExitCode::FAILURE
}
