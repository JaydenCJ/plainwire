//! End-to-end tests that exercise the compiled `plainwire` binary: the
//! `inspect`, `lint`, `hexdump`, `craft` and `codes` subcommands, their exit
//! codes, stdin/file input, and the craft→inspect round trip that proves a
//! deliberately ambiguous request is detected. Everything runs offline against
//! in-memory bytes and temporary files.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_plainwire")
}

/// Run the binary with `args`, no stdin.
fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run plainwire")
}

/// Run the binary with `args`, piping `input` to stdin and returning the output.
fn run_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn plainwire");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("failed to write stdin");
    child.wait_with_output().expect("failed to wait")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn version_and_help() {
    let v = run(&["--version"]);
    assert!(v.status.success());
    assert_eq!(
        stdout(&v).trim(),
        format!("plainwire {}", env!("CARGO_PKG_VERSION"))
    );

    let h = run(&["--help"]);
    assert!(h.status.success());
    let text = stdout(&h);
    assert!(text.contains("COMMANDS:"));
    for cmd in ["inspect", "lint", "hexdump", "craft", "codes"] {
        assert!(text.contains(cmd), "help must mention '{cmd}'");
    }
}

#[test]
fn inspect_annotates_a_request_from_stdin() {
    let out = run_stdin(
        &["inspect", "-"],
        b"POST /login HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
    );
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("plainwire — request"));
    assert!(text.contains("method   POST"));
    assert!(text.contains("framing   content-length"));
    assert!(text.contains("findings: 0 error"));
}

#[test]
fn inspect_json_is_structured() {
    let out = run_stdin(
        &["inspect", "--json"],
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    );
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("\"message\""));
    assert!(text.contains("\"findings\""));
    assert!(text.contains("\"code\": \"PW001\""));
    // Balanced braces are a cheap structural sanity check.
    assert_eq!(text.matches('{').count(), text.matches('}').count());
}

#[test]
fn inspect_reads_a_file() {
    let dir = std::env::temp_dir().join(format!("plainwire-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("req.http");
    std::fs::write(&path, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
    let out = run(&["inspect", path.to_str().unwrap()]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("no framing ambiguities detected"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn lint_exit_codes_and_fail_on_threshold() {
    // A clean request: exit 0.
    let clean = run_stdin(&["lint"], b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(clean.status.code(), Some(0));

    // A CL/TE desync: exit 1.
    let desync = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG";
    let bad = run_stdin(&["lint"], desync);
    assert_eq!(bad.status.code(), Some(1));
    assert!(stdout(&bad).contains("PW001"));

    // --fail-on never reports the finding but never fails the build.
    let never = run_stdin(&["lint", "--fail-on", "never"], desync);
    assert_eq!(never.status.code(), Some(0));
    assert!(stdout(&never).contains("PW001"));
}

#[test]
fn craft_round_trips_clean_through_inspect() {
    let crafted = run(&[
        "craft",
        "-X",
        "POST",
        "--host",
        "example.test",
        "--body",
        "payload",
    ]);
    assert!(crafted.status.success());
    assert!(crafted.stdout.windows(2).any(|w| w == b"\r\n"));
    let inspected = run_stdin(&["inspect", "-"], &crafted.stdout);
    assert!(stdout(&inspected).contains("findings: 0 error"));
}

#[test]
fn craft_smuggle_gadget_is_detected() {
    // The write half and the read half agree: a crafted gadget lints as a desync.
    let gadget = run(&["craft", "--smuggle", "cl.te"]);
    assert!(gadget.status.success());
    let linted = run_stdin(&["lint", "--request"], &gadget.stdout);
    assert_eq!(linted.status.code(), Some(1));
    let text = stdout(&linted);
    assert!(text.contains("PW001"));
    assert!(text.contains("PW017"));
}

#[test]
fn hexdump_labels_regions() {
    let out = run_stdin(&["hexdump"], b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("region"));
    assert!(text.contains("start-line"));
    assert!(text.contains("00000000"));
}

#[test]
fn codes_lists_the_catalog() {
    let out = run(&["codes"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("PW001"));
    assert!(text.contains("both-cl-te"));
    assert!(text.contains("--smuggle"));
}

#[test]
fn unknown_command_is_a_usage_error() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
}
