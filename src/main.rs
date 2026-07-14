//! plainwire binary entry point.

fn main() {
    restore_default_sigpipe();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(plainwire::cli::dispatch(argv));
}

/// Restore the default `SIGPIPE` disposition on Unix.
///
/// The Rust runtime installs `SIG_IGN` for `SIGPIPE`, which turns a closed
/// downstream pipe into an `EPIPE` write error that the `print!` family
/// escalates into a panic (a "failed printing to stdout: Broken pipe"
/// backtrace). Resetting to `SIG_DFL` makes plainwire terminate quietly when a
/// reader goes away — `plainwire codes | head`, `plainwire hexdump big.http |
/// less` and quitting early — exactly like a standard Unix filter. Kept as a
/// tiny raw FFI call so the crate stays dependency-free.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SIGPIPE == 13 and SIG_DFL == 0 on every Unix target Rust supports.
    const SIGPIPE: i32 = 13;
    const SIG_DFL: usize = 0;
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: `signal` with SIG_DFL is async-signal-safe and simply restores the
    // kernel default; no Rust invariants are involved.
    unsafe {
        signal(SIGPIPE, SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}
