//! Command-line interface: argument parsing and the `inspect`, `lint`,
//! `hexdump`, `craft` and `codes` subcommands. Kept dependency-free on purpose.

use crate::analyze;
use crate::annotate::{self, Palette};
use crate::craft::{self, ClMode, CraftSpec, Gadget};
use crate::findings::{Counts, Severity, CATALOG};
use crate::hexdump;
use crate::json;
use crate::message::ParseMode;
use std::io::{IsTerminal, Read, Write};
use std::path::Path;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
plainwire — craft and inspect raw HTTP/1.1 exchanges byte-by-byte

USAGE:
    plainwire <COMMAND> [OPTIONS]

COMMANDS:
    inspect   Parse a raw HTTP/1.1 message and print an annotated breakdown
    lint      Report only the framing/smuggling findings (exit non-zero on error)
    hexdump   Print an annotated hex dump with per-region labels
    craft     Build a raw HTTP/1.1 request (incl. deliberately ambiguous gadgets)
    codes     List the finding codes and what they mean

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print version

Input is a FILE argument or '-' / no argument to read stdin.
Run 'plainwire <COMMAND> --help' for command-specific options.";

const INSPECT_HELP: &str = "\
plainwire inspect — annotated byte-level breakdown of a message

USAGE:
    plainwire inspect [FILE] [OPTIONS]

OPTIONS:
        --request        Parse the start-line as a request (default: auto-detect)
        --response       Parse the start-line as a response
        --json           Emit the full analysis as JSON
        --hex            Append an annotated hex dump
        --color          Force ANSI colour
        --no-color       Disable ANSI colour (default when piped)
    -h, --help           Print this help";

const LINT_HELP: &str = "\
plainwire lint — report framing/smuggling findings and set the exit code

USAGE:
    plainwire lint [FILE] [OPTIONS]

OPTIONS:
        --request           Parse as a request (default: auto-detect)
        --response          Parse as a response
        --json              Emit findings as a JSON array
        --fail-on <LEVEL>   Exit non-zero at this severity or worse
                            (error|warn|info|never) [default: error]
    -h, --help              Print this help

Exit code is 1 when a finding at or above --fail-on is present, else 0.";

const HEXDUMP_HELP: &str = "\
plainwire hexdump — annotated hex dump with region labels

USAGE:
    plainwire hexdump [FILE] [OPTIONS]

OPTIONS:
        --request     Parse as a request (default: auto-detect)
        --response    Parse as a response
    -h, --help        Print this help";

const CRAFT_HELP: &str = "\
plainwire craft — build a raw HTTP/1.1 request on stdout

USAGE:
    plainwire craft [OPTIONS]

OPTIONS:
    -X, --method <M>        Request method [default: GET, POST when a body is set]
        --target <T>        Request target [default: /]
        --host <H>          Host header value [default: example.test]
        --http <V>          HTTP version token [default: HTTP/1.1]
    -H, --header <K: V>     Add a header (repeatable)
        --body <STR>        Request body (implies POST unless -X is given)
        --chunked           Encode the body with Transfer-Encoding: chunked
        --no-content-length Do not emit a Content-Length header
        --smuggle <GADGET>  Emit a known desync gadget instead of a normal
                            request (cl.te|te.cl|te.te|space-colon|bare-lf)
    -h, --help              Print this help

Output is raw wire bytes; pipe it into netcat or back into 'plainwire inspect -'.";

/// Error carrying the intended process exit code.
pub struct CliError {
    pub message: String,
    pub code: i32,
}

fn usage_err(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        code: 2,
    }
}

fn run_err(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
        code: 1,
    }
}

/// Entry point used by `main`. Returns the process exit code.
pub fn dispatch(argv: Vec<String>) -> i32 {
    match run_cli(argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("plainwire: {}", e.message);
            e.code
        }
    }
}

fn run_cli(argv: Vec<String>) -> Result<i32, CliError> {
    let Some(command) = argv.first().cloned() else {
        println!("{HELP}");
        return Err(usage_err("missing command"));
    };
    let rest = &argv[1..];
    match command.as_str() {
        "-h" | "--help" | "help" => {
            println!("{HELP}");
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("plainwire {VERSION}");
            Ok(0)
        }
        "inspect" => cmd_inspect(rest),
        "lint" => cmd_lint(rest),
        "hexdump" => cmd_hexdump(rest),
        "craft" => cmd_craft(rest),
        "codes" => cmd_codes(rest),
        other => Err(usage_err(format!(
            "unknown command '{other}' (try 'plainwire --help')"
        ))),
    }
}

/// Read the input message from a file path or stdin (`-` or absent).
fn read_input(path: Option<&str>) -> Result<Vec<u8>, CliError> {
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| run_err(format!("cannot read stdin: {e}")))?;
            Ok(buf)
        }
        Some(p) => {
            std::fs::read(Path::new(p)).map_err(|e| run_err(format!("cannot read {p}: {e}")))
        }
    }
}

/// Shared flag state for the read-side commands.
struct ReadOpts {
    path: Option<String>,
    mode: ParseMode,
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    std::io::stdout()
        .write_all(bytes)
        .map_err(|e| run_err(format!("cannot write output: {e}")))
}

fn cmd_inspect(args: &[String]) -> Result<i32, CliError> {
    let mut opts = ReadOpts {
        path: None,
        mode: ParseMode::Auto,
    };
    let mut json_out = false;
    let mut with_hex = false;
    let mut color: Option<bool> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--request" => opts.mode = ParseMode::Request,
            "--response" => opts.mode = ParseMode::Response,
            "--json" => json_out = true,
            "--hex" => with_hex = true,
            "--color" => color = Some(true),
            "--no-color" => color = Some(false),
            "-h" | "--help" => {
                println!("{INSPECT_HELP}");
                return Ok(0);
            }
            p if !p.starts_with('-') && opts.path.is_none() => opts.path = Some(p.to_string()),
            "-" if opts.path.is_none() => opts.path = Some("-".to_string()),
            other => return Err(usage_err(format!("unknown option '{other}' for inspect"))),
        }
        i += 1;
    }
    let buf = read_input(opts.path.as_deref())?;
    let analysis = analyze(&buf, opts.mode);
    if json_out {
        write_stdout(json::to_json(&analysis).as_bytes())?;
        return Ok(0);
    }
    let enabled = color.unwrap_or_else(|| std::io::stdout().is_terminal());
    let pal = Palette::new(enabled);
    print!("{}", annotate::render(&analysis, &pal));
    if with_hex {
        println!();
        print!("{}", hexdump::render(&analysis.message, &buf));
    }
    Ok(0)
}

fn parse_fail_on(v: &str) -> Result<Option<Severity>, CliError> {
    match v.to_ascii_lowercase().as_str() {
        "error" => Ok(Some(Severity::Error)),
        "warn" => Ok(Some(Severity::Warn)),
        "info" => Ok(Some(Severity::Info)),
        "never" => Ok(None),
        other => Err(usage_err(format!(
            "--fail-on expects error|warn|info|never, got '{other}'"
        ))),
    }
}

fn cmd_lint(args: &[String]) -> Result<i32, CliError> {
    let mut opts = ReadOpts {
        path: None,
        mode: ParseMode::Auto,
    };
    let mut json_out = false;
    let mut fail_on = Some(Severity::Error);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--request" => opts.mode = ParseMode::Request,
            "--response" => opts.mode = ParseMode::Response,
            "--json" => json_out = true,
            "--fail-on" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| usage_err("--fail-on requires a value"))?;
                fail_on = parse_fail_on(v)?;
            }
            "-h" | "--help" => {
                println!("{LINT_HELP}");
                return Ok(0);
            }
            p if !p.starts_with('-') && opts.path.is_none() => opts.path = Some(p.to_string()),
            "-" if opts.path.is_none() => opts.path = Some("-".to_string()),
            other => return Err(usage_err(format!("unknown option '{other}' for lint"))),
        }
        i += 1;
    }
    let buf = read_input(opts.path.as_deref())?;
    let analysis = analyze(&buf, opts.mode);
    if json_out {
        write_stdout(json::findings_to_json(&analysis.findings).as_bytes())?;
    } else {
        let pal = Palette::new(std::io::stdout().is_terminal());
        print!("{}", annotate::render_findings(&analysis.findings, &pal));
    }
    let counts = Counts::of(&analysis.findings);
    let failed = match fail_on {
        Some(threshold) => counts.any_at_least(threshold),
        None => false,
    };
    Ok(if failed { 1 } else { 0 })
}

fn cmd_hexdump(args: &[String]) -> Result<i32, CliError> {
    let mut opts = ReadOpts {
        path: None,
        mode: ParseMode::Auto,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--request" => opts.mode = ParseMode::Request,
            "--response" => opts.mode = ParseMode::Response,
            "-h" | "--help" => {
                println!("{HEXDUMP_HELP}");
                return Ok(0);
            }
            p if !p.starts_with('-') && opts.path.is_none() => opts.path = Some(p.to_string()),
            "-" if opts.path.is_none() => opts.path = Some("-".to_string()),
            other => return Err(usage_err(format!("unknown option '{other}' for hexdump"))),
        }
        i += 1;
    }
    let buf = read_input(opts.path.as_deref())?;
    let analysis = analyze(&buf, opts.mode);
    print!("{}", hexdump::render(&analysis.message, &buf));
    Ok(0)
}

/// Consume the value following a flag at `*i`, advancing the cursor.
fn value_at(args: &[String], i: &mut usize, flag: &str) -> Result<String, CliError> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| usage_err(format!("{flag} requires a value")))
}

fn cmd_craft(args: &[String]) -> Result<i32, CliError> {
    let mut spec = CraftSpec::default();
    let mut method_set = false;
    let mut gadget: Option<Gadget> = None;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].clone();
        match tok.as_str() {
            "-X" | "--method" => {
                spec.method = value_at(args, &mut i, "--method")?;
                method_set = true;
            }
            "--target" => spec.target = value_at(args, &mut i, "--target")?,
            "--host" => spec.host = value_at(args, &mut i, "--host")?,
            "--http" => spec.version = value_at(args, &mut i, "--http")?,
            "-H" | "--header" => {
                let raw = value_at(args, &mut i, "--header")?;
                let (k, v) = raw.split_once(':').ok_or_else(|| {
                    usage_err(format!("--header expects 'Key: Value', got '{raw}'"))
                })?;
                spec.headers
                    .push((k.trim().to_string(), v.trim().to_string()));
            }
            "--body" => {
                spec.body = value_at(args, &mut i, "--body")?.into_bytes();
                if !method_set {
                    spec.method = "POST".to_string();
                }
            }
            "--chunked" => spec.chunked = true,
            "--no-content-length" => spec.content_length = ClMode::Omit,
            "--smuggle" => {
                let name = value_at(args, &mut i, "--smuggle")?;
                gadget = Some(
                    Gadget::parse(&name)
                        .ok_or_else(|| usage_err(format!("unknown gadget '{name}'")))?,
                );
            }
            "-h" | "--help" => {
                println!("{CRAFT_HELP}");
                return Ok(0);
            }
            other => return Err(usage_err(format!("unknown option '{other}' for craft"))),
        }
        i += 1;
    }
    let bytes = match gadget {
        Some(g) => craft::gadget(g, &spec.host, &spec.target),
        None => craft::build(&spec),
    };
    write_stdout(&bytes)?;
    Ok(0)
}

fn cmd_codes(args: &[String]) -> Result<i32, CliError> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("plainwire codes — list the finding codes\n\nUSAGE:\n    plainwire codes");
        return Ok(0);
    }
    println!("plainwire finding codes\n");
    for s in CATALOG {
        println!("{}  {:<5}  {}", s.code, s.severity.label(), s.slug);
        println!("       {}", s.title);
        println!("       {}\n", s.description);
    }
    println!("smuggling gadgets (plainwire craft --smuggle <name>):");
    for (name, desc) in Gadget::all() {
        println!("    {name:<12}  {desc}");
    }
    Ok(0)
}
