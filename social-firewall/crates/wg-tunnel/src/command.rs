//! Abstracts running `wg`/`ip` behind a trait, so the whole reconcile/
//! apply flow is testable without root or real WireGuard/network-
//! namespace state. Deliberately a separate, small trait from
//! `nft-enforcer`'s own `CommandRunner` (which is explicitly scoped to
//! `nft` only, per that crate's own module doc) rather than a shared
//! abstraction crate for two callers — cheaper to duplicate ~90 lines
//! than to introduce a new crate boundary for this.

use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self { success: true, stdout: stdout.into(), stderr: String::new() }
    }
    pub fn err(stderr: impl Into<String>) -> Self {
        Self { success: false, stdout: String::new(), stderr: stderr.into() }
    }
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandOutput;
}

/// Real implementation — shells out with a bounded wait: the child is
/// killed if it hasn't exited by `timeout`, so a hung `wg`/`ip` invocation
/// can never block the caller indefinitely.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> CommandOutput {
        use std::io::Read;
        use std::process::{Command, Stdio};

        let mut child = match Command::new(program).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(e) => return CommandOutput::err(format!("failed to spawn {program}: {e}")),
        };

        let deadline = std::time::Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break None,
            }
        };

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut stdout);
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut stderr);
        }

        match status {
            Some(status) => CommandOutput { success: status.success(), stdout, stderr },
            None => CommandOutput { success: false, stdout, stderr: format!("{program} timed out after {timeout:?}") },
        }
    }
}

type MatchFn = Box<dyn Fn(&str, &[String]) -> bool + Send + Sync>;

/// Test double: every call is recorded (for assertions on exactly which
/// commands ran, in what order, with what arguments) and, by default,
/// succeeds with empty output. `fail_next_matching` queues a one-shot
/// failure for the next call whose program+args satisfy the predicate.
pub struct FakeCommandRunner {
    calls: std::sync::Mutex<Vec<(String, Vec<String>)>>,
    failures: std::sync::Mutex<Vec<MatchFn>>,
    default_stdout: std::sync::Mutex<String>,
}

impl FakeCommandRunner {
    pub fn new_all_success() -> Self {
        Self { calls: std::sync::Mutex::new(Vec::new()), failures: std::sync::Mutex::new(Vec::new()), default_stdout: std::sync::Mutex::new(String::new()) }
    }

    pub fn fail_next_matching(&self, pred: impl Fn(&str, &[String]) -> bool + Send + Sync + 'static) {
        self.failures.lock().unwrap().push(Box::new(pred));
    }

    /// Stdout returned by every otherwise-unconfigured successful call —
    /// used to simulate `wg show ... dump` returning existing peer state.
    pub fn set_default_stdout(&self, text: impl Into<String>) {
        *self.default_stdout.lock().unwrap() = text.into();
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for FakeCommandRunner {
    fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> CommandOutput {
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        self.calls.lock().unwrap().push((program.to_string(), args_owned.clone()));

        let mut failures = self.failures.lock().unwrap();
        if let Some(pos) = failures.iter().position(|pred| pred(program, &args_owned)) {
            let _ = failures.remove(pos);
            return CommandOutput::err(format!("simulated failure for {program} {args_owned:?}"));
        }
        drop(failures);

        CommandOutput::ok(self.default_stdout.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_runner_records_calls_in_order() {
        let runner = FakeCommandRunner::new_all_success();
        runner.run("wg", &["show", "sf0", "dump"], Duration::from_secs(1));
        runner.run("ip", &["link", "show", "sf0"], Duration::from_secs(1));
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "wg");
        assert_eq!(calls[1].0, "ip");
    }

    #[test]
    fn fail_next_matching_only_fails_once() {
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| p == "wg" && a.first().map(String::as_str) == Some("set"));

        let first = runner.run("wg", &["set", "sf0", "peer", "abc"], Duration::from_secs(1));
        assert!(!first.success);
        let second = runner.run("wg", &["set", "sf0", "peer", "abc"], Duration::from_secs(1));
        assert!(second.success, "the failure should be consumed after the first matching call");
    }

    #[test]
    fn system_runner_reports_failure_for_a_missing_binary() {
        let runner = SystemCommandRunner;
        let out = runner.run("definitely-not-a-real-binary-xyz", &[], Duration::from_secs(1));
        assert!(!out.success);
    }

    #[test]
    fn system_runner_captures_stdout_of_a_real_command() {
        let runner = SystemCommandRunner;
        let out = runner.run("echo", &["hello"], Duration::from_secs(1));
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn system_runner_times_out_a_hanging_command() {
        let runner = SystemCommandRunner;
        let start = std::time::Instant::now();
        let out = runner.run("sleep", &["5"], Duration::from_millis(200));
        assert!(!out.success);
        assert!(start.elapsed() < Duration::from_secs(2), "must not wait for the full sleep duration");
    }
}
