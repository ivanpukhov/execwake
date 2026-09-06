use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

use crate::session::CollectorRequest;

#[derive(Debug)]
pub struct Cli {
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Run(RunArgs),
    Diff(DiffArgs),
}

#[derive(Debug)]
pub struct RunArgs {
    pub command: Vec<OsString>,
    pub node_enrichment: bool,
    pub collector: CollectorRequest,
    pub output: Option<PathBuf>,
}

#[derive(Debug)]
pub struct DiffArgs {
    pub before: PathBuf,
    pub after: PathBuf,
    pub output: DiffOutput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffOutput {
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelpTopic {
    Root,
    Run,
    Diff,
}

#[derive(Debug)]
pub enum ParseResult {
    Command(Cli),
    Help(HelpTopic),
    Version,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

impl Cli {
    pub fn parse_env() -> Result<ParseResult, ParseError> {
        Self::parse_from(std::env::args_os())
    }

    pub fn parse_from<I, T>(arguments: I) -> Result<ParseResult, ParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut arguments = arguments.into_iter().map(Into::into);
        arguments.next();

        let Some(subcommand) = arguments.next() else {
            return Err(ParseError::new("a subcommand is required"));
        };

        if subcommand == OsStr::new("--help") || subcommand == OsStr::new("-h") {
            return Ok(ParseResult::Help(HelpTopic::Root));
        }
        if subcommand == OsStr::new("--version") || subcommand == OsStr::new("-V") {
            return Ok(ParseResult::Version);
        }

        match subcommand.to_str() {
            Some("run") => parse_run(arguments.collect()),
            Some("diff") => parse_diff(arguments.collect()),
            Some(other) => Err(ParseError::new(format!("unknown subcommand: {other}"))),
            None => Err(ParseError::new("subcommand is not valid UTF-8")),
        }
    }
}

pub fn help_text(topic: HelpTopic) -> &'static str {
    match topic {
        HelpTopic::Root => {
            "ExecWake\n\nUsage:\n  execwake run [--node-enrichment] [--collector auto|ebpf|ptrace] [--output <path>] [--] <command> [arguments...]\n  execwake diff [--json] <before> <after>\n"
        }
        HelpTopic::Run => {
            "Usage: execwake run [--node-enrichment] [--collector auto|ebpf|ptrace] [--output <path>] [--] <command> [arguments...]\n"
        }
        HelpTopic::Diff => "Usage: execwake diff [--json] <before> <after>\n",
    }
}

fn parse_run(mut arguments: Vec<OsString>) -> Result<ParseResult, ParseError> {
    if arguments.first().map(OsString::as_os_str) == Some(OsStr::new("--help"))
        || arguments.first().map(OsString::as_os_str) == Some(OsStr::new("-h"))
    {
        return Ok(ParseResult::Help(HelpTopic::Run));
    }

    let mut node_enrichment = false;
    let mut collector = CollectorRequest::Auto;
    let mut output = None;
    loop {
        match arguments.first().map(OsString::as_os_str) {
            Some(value) if value == OsStr::new("--node-enrichment") => {
                node_enrichment = true;
                arguments.remove(0);
            }
            Some(value) if value == OsStr::new("--collector") => {
                if arguments.len() < 2 {
                    return Err(ParseError::new("--collector requires a value"));
                }
                let value = arguments
                    .get(1)
                    .and_then(|value| value.to_str())
                    .and_then(CollectorRequest::parse)
                    .ok_or_else(|| ParseError::new("collector must be auto, ebpf, or ptrace"))?;
                collector = value;
                arguments.drain(0..2);
            }
            Some(value) if value == OsStr::new("--output") => {
                if output.is_some() {
                    return Err(ParseError::new("--output may only be specified once"));
                }
                if arguments.len() < 2 {
                    return Err(ParseError::new("--output requires a path"));
                }
                output = Some(PathBuf::from(arguments.remove(1)));
                arguments.remove(0);
            }
            Some(value) if value == OsStr::new("--") => {
                arguments.remove(0);
                break;
            }
            _ => break,
        }
    }

    if arguments.is_empty() {
        return Err(ParseError::new("run requires a command"));
    }

    Ok(ParseResult::Command(Cli {
        command: Command::Run(RunArgs {
            command: arguments,
            node_enrichment,
            collector,
            output,
        }),
    }))
}

fn parse_diff(mut arguments: Vec<OsString>) -> Result<ParseResult, ParseError> {
    if arguments.first().map(OsString::as_os_str) == Some(OsStr::new("--help"))
        || arguments.first().map(OsString::as_os_str) == Some(OsStr::new("-h"))
    {
        return Ok(ParseResult::Help(HelpTopic::Diff));
    }

    let output = if arguments.first().map(OsString::as_os_str) == Some(OsStr::new("--json")) {
        arguments.remove(0);
        if arguments.first().map(OsString::as_os_str) == Some(OsStr::new("--json")) {
            return Err(ParseError::new("--json may only be specified once"));
        }
        DiffOutput::Json
    } else {
        DiffOutput::Human
    };

    if arguments.len() != 2 {
        return Err(ParseError::new("diff requires two session paths"));
    }

    let after = PathBuf::from(arguments.pop().expect("length was checked"));
    let before = PathBuf::from(arguments.pop().expect("length was checked"));

    Ok(ParseResult::Command(Cli {
        command: Command::Diff(DiffArgs {
            before,
            after,
            output,
        }),
    }))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use super::{Cli, Command, DiffOutput, HelpTopic, ParseResult};
    use crate::session::CollectorRequest;

    #[test]
    fn parses_run_arguments_without_interpreting_command_flags() {
        let result =
            Cli::parse_from(["execwake", "run", "npm", "install", "--save-dev", "example"])
                .expect("run arguments should parse");

        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(
            args.command,
            [
                OsStr::new("npm"),
                OsStr::new("install"),
                OsStr::new("--save-dev"),
                OsStr::new("example"),
            ]
        );
    }

    #[test]
    fn accepts_a_separator_before_the_command() {
        let result = Cli::parse_from(["execwake", "run", "--", "printf", "--help"])
            .expect("run arguments should parse");

        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(args.command, [OsStr::new("printf"), OsStr::new("--help")]);
        assert!(!args.node_enrichment);
        assert_eq!(args.collector, CollectorRequest::Auto);
        assert_eq!(args.output, None);
    }

    #[test]
    fn enables_node_enrichment_only_before_the_separator() {
        let result = Cli::parse_from([
            "execwake",
            "run",
            "--node-enrichment",
            "--",
            "node",
            "fixture.cjs",
        ])
        .expect("run arguments should parse");
        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert!(args.node_enrichment);
        assert_eq!(
            args.command,
            [OsStr::new("node"), OsStr::new("fixture.cjs")]
        );

        let result = Cli::parse_from(["execwake", "run", "--", "--node-enrichment", "fixture.cjs"])
            .expect("argv after the separator should parse");
        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert!(!args.node_enrichment);
        assert_eq!(
            args.command,
            [OsStr::new("--node-enrichment"), OsStr::new("fixture.cjs")]
        );
    }

    #[test]
    fn selects_a_collector_only_before_the_separator() {
        let result = Cli::parse_from([
            "execwake",
            "run",
            "--collector",
            "ptrace",
            "--",
            "command",
            "--collector",
            "ebpf",
        ])
        .expect("collector selection should parse");
        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(args.collector, CollectorRequest::Ptrace);
        assert_eq!(
            args.command,
            [
                OsStr::new("command"),
                OsStr::new("--collector"),
                OsStr::new("ebpf")
            ]
        );
    }

    #[test]
    fn parses_an_output_path_only_before_the_separator() {
        let result = Cli::parse_from([
            "execwake",
            "run",
            "--output",
            "trace.sqlite3",
            "--",
            "command",
            "--output",
            "child-value",
        ])
        .expect("the output path should parse");
        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(args.output.as_deref(), Some(Path::new("trace.sqlite3")));
        assert_eq!(
            args.command,
            [
                OsStr::new("command"),
                OsStr::new("--output"),
                OsStr::new("child-value")
            ]
        );
        assert!(Cli::parse_from(["execwake", "run", "--output"]).is_err());
        assert!(Cli::parse_from([
            "execwake",
            "run",
            "--output",
            "one.sqlite3",
            "--output",
            "two.sqlite3",
            "command"
        ])
        .is_err());
    }

    #[test]
    fn rejects_invalid_collector_selection() {
        assert!(Cli::parse_from(["execwake", "run", "--collector"]).is_err());
        assert!(
            Cli::parse_from(["execwake", "run", "--collector", "unknown", "--", "command"])
                .is_err()
        );
    }

    #[test]
    fn preserves_shell_metacharacters_as_individual_arguments() {
        let result =
            Cli::parse_from(["execwake", "run", "--", "printf", "two words", "$HOME", ";"])
                .expect("run arguments should parse");

        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };

        assert_eq!(
            args.command,
            [
                OsStr::new("printf"),
                OsStr::new("two words"),
                OsStr::new("$HOME"),
                OsStr::new(";"),
            ]
        );
    }

    #[test]
    fn parses_diff_session_paths() {
        let result = Cli::parse_from(["execwake", "diff", "before.sqlite3", "after.sqlite3"])
            .expect("diff arguments should parse");

        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Diff(args) = cli.command else {
            panic!("expected diff command");
        };

        assert_eq!(args.before, Path::new("before.sqlite3"));
        assert_eq!(args.after, Path::new("after.sqlite3"));
        assert_eq!(args.output, DiffOutput::Human);
    }

    #[test]
    fn selects_json_diff_output() {
        let result = Cli::parse_from([
            "execwake",
            "diff",
            "--json",
            "before.sqlite3",
            "after.sqlite3",
        ])
        .expect("JSON diff arguments should parse");

        let ParseResult::Command(cli) = result else {
            panic!("expected command");
        };
        let Command::Diff(args) = cli.command else {
            panic!("expected diff command");
        };

        assert_eq!(args.before, Path::new("before.sqlite3"));
        assert_eq!(args.after, Path::new("after.sqlite3"));
        assert_eq!(args.output, DiffOutput::Json);
        assert!(
            Cli::parse_from(["execwake", "diff", "--json", "--json", "after.sqlite3"]).is_err()
        );
    }

    #[test]
    fn parses_help_without_a_command() {
        let result = Cli::parse_from(["execwake", "--help"]).expect("help should parse");
        assert!(matches!(result, ParseResult::Help(HelpTopic::Root)));
    }

    #[test]
    fn rejects_run_without_a_command() {
        assert!(Cli::parse_from(["execwake", "run"]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommands() {
        assert!(Cli::parse_from(["execwake", "show"]).is_err());
    }
}
