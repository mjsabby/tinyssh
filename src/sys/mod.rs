//! Platform layer: OS randomness and the session's process.
//!
//! Both back ends expose the same shape: a [`Process`] with an input half
//! (`write`), an output half (`read` returning [`Chunk`]s) and a waiter, kept
//! as separate fields so the driver can await all three at once.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{Input, Output, Process, Waiter, os_random};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{Input, Output, Process, Waiter, os_random};

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("tinyssh supports Linux and Windows only");

/// One read of process output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chunk {
    Stdout(usize),
    Stderr(usize),
    /// All output has been delivered.
    Eof,
}

/// Whether `shell` is `cmd.exe`, which takes `/c` (and its own quoting)
/// rather than `-c`.
pub(crate) fn is_cmd(shell: &str) -> bool {
    let name = shell
        .trim_matches('"')
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(shell);
    name.eq_ignore_ascii_case("cmd.exe") || name.eq_ignore_ascii_case("cmd")
}

/// Login-shell argument for `exec` requests: `/c` for `cmd.exe`, `-c` for
/// POSIX-style shells (including PowerShell, which accepts `-c`).
#[cfg(target_os = "linux")]
pub(crate) fn command_flag(shell: &str) -> &'static str {
    match is_cmd(shell) {
        true => "/c",
        false => "-c",
    }
}

/// The Windows command line that runs `command` with `shell`, or just the
/// interactive `shell`. `cmd.exe` parses its command line itself: with `/s`
/// it removes exactly the outer quotes added here and runs the rest
/// verbatim. Other shells get the command as the one argument after `-c`,
/// quoted for the C runtime's parsing (that of `CommandLineToArgvW`).
#[cfg(any(windows, test))]
pub(crate) fn windows_command_line(shell: &str, command: Option<&[u8]>) -> String {
    let mut line = quote_program(shell);
    match command {
        Some(command) if is_cmd(shell) => {
            line.push_str(" /s /c \"");
            line.push_str(&String::from_utf8_lossy(command));
            line.push('"');
        }
        Some(command) => {
            line.push_str(" -c ");
            quote_arg(&mut line, &String::from_utf8_lossy(command));
        }
        None => {}
    }
    line
}

/// A program path at the start of a command line, where `CreateProcessW`
/// splits at the first space unless it is quoted (paths contain no quotes).
#[cfg(any(windows, test))]
fn quote_program(path: &str) -> String {
    match path.contains([' ', '\t']) && !path.starts_with('"') {
        true => format!("\"{path}\""),
        false => path.to_owned(),
    }
}

/// Appends `arg` in quotes, so that the C runtime reads it back as one
/// argument: a quote becomes `\"`, and the backslashes before it or before
/// the closing quote are doubled.
#[cfg(any(windows, test))]
fn quote_arg(line: &mut String, arg: &str) {
    line.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes = backslashes.saturating_add(1),
            '"' => {
                let escaped = backslashes.saturating_mul(2).saturating_add(1);
                line.extend(core::iter::repeat_n('\\', escaped));
                line.push('"');
                backslashes = 0;
            }
            c => {
                line.extend(core::iter::repeat_n('\\', backslashes));
                line.push(c);
                backslashes = 0;
            }
        }
    }
    line.extend(core::iter::repeat_n('\\', backslashes.saturating_mul(2)));
    line.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The C runtime's parsing of the arguments after the program name
    /// (the rules of `CommandLineToArgvW`), for checking `quote_arg`.
    fn parse_args(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut chars = line.chars().peekable();
        loop {
            while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
            if chars.peek().is_none() {
                return args;
            }
            let (mut arg, mut quoted) = (String::new(), false);
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        let mut n = 1;
                        while chars.next_if_eq(&'\\').is_some() {
                            n += 1;
                        }
                        if chars.peek() == Some(&'"') {
                            arg.extend(std::iter::repeat_n('\\', n / 2));
                            if n % 2 == 1 {
                                arg.push('"');
                                chars.next();
                            }
                        } else {
                            arg.extend(std::iter::repeat_n('\\', n));
                        }
                    }
                    '"' if quoted && chars.peek() == Some(&'"') => {
                        arg.push('"');
                        chars.next();
                    }
                    '"' => quoted = !quoted,
                    ' ' | '\t' if !quoted => break,
                    c => arg.push(c),
                }
            }
            args.push(arg);
        }
    }

    #[test]
    fn windows_command_lines() {
        let command = br#""C:\Program Files\App\app.exe" "hello world""#;
        assert_eq!(
            windows_command_line(r"C:\Windows\System32\cmd.exe", Some(command)),
            r#"C:\Windows\System32\cmd.exe /s /c ""C:\Program Files\App\app.exe" "hello world"""#
        );
        assert_eq!(
            windows_command_line(r"C:\Program Files\Git\bin\bash.exe", Some(b"echo hello")),
            r#""C:\Program Files\Git\bin\bash.exe" -c "echo hello""#
        );
        assert_eq!(windows_command_line("cmd.exe", None), "cmd.exe");
        // Other shells get each command back as exactly one argument.
        for command in [
            "echo hello",
            r#"Write-Output "hello world""#,
            r"dir C:\",
            r#"a\"b"#,
            r#"a\\"b c\\"#,
            r#"\\server\share "x" \"#,
            "",
            "tab\tand\nnewline",
            r#""""#,
        ] {
            let line = windows_command_line("pwsh.exe", Some(command.as_bytes()));
            let rest = line.strip_prefix("pwsh.exe ").unwrap();
            assert_eq!(parse_args(rest), ["-c", command], "{line}");
        }
    }
}
