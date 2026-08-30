use std::process;

use execwake::cli::{help_text, Cli, Command, HelpTopic, ParseResult};

fn main() {
    let result = match Cli::parse_env() {
        Ok(result) => result,
        Err(error) => {
            eprintln!("error: {error}\n\n{}", help_text(HelpTopic::Root));
            process::exit(2);
        }
    };

    let cli = match result {
        ParseResult::Command(cli) => cli,
        ParseResult::Help(topic) => {
            print!("{}", help_text(topic));
            return;
        }
        ParseResult::Version => {
            println!("execwake {}", env!("CARGO_PKG_VERSION"));
            return;
        }
    };

    match cli.command {
        Command::Run(args) => match execwake::runner::run(args.command) {
            Ok(result) => {
                eprintln!("Session: {}", result.session.database().display());
                process::exit(result.status.code().unwrap_or(1));
            }
            Err(error) => {
                eprintln!("error: {error}");
                process::exit(1);
            }
        },
        Command::Diff(_) => {
            eprintln!("session comparison is not available yet");
            process::exit(1);
        }
    }
}
