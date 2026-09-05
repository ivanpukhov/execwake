mod report_launch;

use std::env;
use std::ffi::OsString;
use std::process;

use execwake::cli::{help_text, Cli, Command, HelpTopic, ParseResult};

fn main() {
    let arguments: Vec<OsString> = env::args_os().collect();
    if let Some(result) = report_launch::serve_if_requested(&arguments) {
        if let Err(error) = result {
            eprintln!("error: report server failed: {error}");
            process::exit(1);
        }
        return;
    }

    let result = match Cli::parse_from(arguments) {
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
        Command::Run(args) => {
            match execwake::runner::run(args.command, args.node_enrichment, args.collector) {
                Ok(result) => {
                    if let Err(error) = report_launch::print_run_summary(&result.session) {
                        eprintln!("Summary unavailable: {error}");
                        report_launch::print_session_path(&result.session);
                    }
                    if result.status.code().is_some() {
                        report_launch::present(&result.session);
                    }
                    execwake::runner::exit_with_status(result.status);
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    match &error {
                        execwake::runner::RunError::Collector { session, .. }
                        | execwake::runner::RunError::Command { session, .. } => {
                            eprintln!("Session: {}", session.display());
                        }
                        _ => {}
                    }
                    process::exit(1);
                }
            }
        }
        Command::Diff(args) => {
            match execwake::semantic_diff::compare_paths(&args.before, &args.after) {
                Ok(diff) => {
                    if let Err(error) =
                        report_launch::present_diff(&args.before, &args.after, &diff)
                    {
                        eprintln!("error: could not present comparison: {error}");
                        process::exit(1);
                    }
                }
                Err(error) => {
                    eprintln!("error: comparison failed: {error}");
                    process::exit(1);
                }
            }
        }
    }
}
