use crate::util::{col_of, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

pub struct IpcDetector;

impl Detector for IpcDetector {
    fn id(&self) -> &'static str {
        "ipc.unix"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            for rule in RULES {
                if let Some(col) = col_of(line, rule.token) {
                    let ev: Evidence = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        format!("reference to `{}`", rule.token),
                        rule.confidence,
                        self.id(),
                    );
                    accrual.add(
                        rule.key,
                        || {
                            Finding::new(
                                rule.dependency,
                                rule.state,
                                rule.severity,
                                rule.description,
                                Some(rule.hint.to_string()),
                            )
                        },
                        ev,
                    );
                }
            }
        }
        accrual.into_findings()
    }
}

struct Rule {
    token: &'static str,
    key: &'static str,
    dependency: PlatformDependency,
    state: CompatibilityState,
    severity: Severity,
    description: &'static str,
    hint: &'static str,
    confidence: f32,
}

const RULES: &[Rule] = &[
    Rule {
        token: "UnixStream",
        key: "unix-socket",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "unix domain socket usage (`UnixStream`)",
        hint: "abstract behind a trait; use named pipes (tokio/windows named pipes or std) on Windows",
        confidence: 0.95,
    },
    Rule {
        token: "UnixListener",
        key: "unix-socket",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "unix domain socket usage (`UnixListener`)",
        hint: "abstract behind a trait; use named pipes on Windows",
        confidence: 0.95,
    },
    Rule {
        token: "UnixDatagram",
        key: "unix-socket",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "unix domain socket usage (`UnixDatagram`)",
        hint: "abstract behind a trait; use UDP loopback or named pipes on Windows",
        confidence: 0.95,
    },
    Rule {
        token: "AF_UNIX",
        key: "unix-socket",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "unix domain socket usage (`AF_UNIX`)",
        hint: "abstract behind a trait; use named pipes on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "sockaddr_un",
        key: "unix-socket",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "unix domain socket address (`sockaddr_un`)",
        hint: "abstract behind a trait; use named pipes on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "inotify",
        key: "fs-watch",
        dependency: PlatformDependency::Kernel,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "Linux inotify filesystem-watch dependency",
        hint: "use the `notify` crate or a ReadDirectoryChangesW backend behind a watch trait",
        confidence: 0.95,
    },
    Rule {
        token: "SIGTERM",
        key: "signals",
        dependency: PlatformDependency::Process,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "POSIX signal handling (SIGTERM)",
        hint: "handle CTRL_CLOSE_EVENT/CTRL_C_EVENT console control handlers on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "SIGINT",
        key: "signals",
        dependency: PlatformDependency::Process,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "POSIX signal handling (SIGINT)",
        hint: "handle CTRL_C_EVENT via console control handlers on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "SIGKILL",
        key: "signals",
        dependency: PlatformDependency::Process,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "POSIX signal handling (SIGKILL)",
        hint: "no equivalent on Windows; use TerminateProcess via job objects or process handles",
        confidence: 0.9,
    },
    Rule {
        token: "libc::kill",
        key: "signals",
        dependency: PlatformDependency::Process,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "process signalling via `kill`",
        hint: "use TerminateProcess / GenerateConsoleCtrlEvent on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "dbus",
        key: "dbus",
        dependency: PlatformDependency::IPC,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "D-Bus IPC dependency",
        hint: "replace with COM, named pipes, or a local gRPC/HTTP loopback on Windows",
        confidence: 0.9,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(content: &str) -> Vec<Finding> {
        IpcDetector.run(
            &FileContext::new("ipc.rs", content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn unix_socket_types_detected() {
        let findings = scan("let l = std::os::unix::net::UnixListener::bind(p)?;");
        let f = &findings[0];
        assert_eq!(f.dependency, PlatformDependency::IPC);
        assert_eq!(f.severity, Severity::Major);
        assert!(f.description.contains("UnixListener"));
    }

    #[test]
    fn inotify_triggers_fs_watch_finding() {
        let findings = scan("use inotify::{Inotify, WatchMask};");
        let f = findings.iter().find(|f| f.description.contains("inotify")).unwrap();
        assert_eq!(f.dependency, PlatformDependency::Kernel);
        assert_eq!(f.severity, Severity::Major);
    }

    #[test]
    fn signals_detected() {
        let findings = scan("unsafe { libc::kill(pid, SIGTERM); }");
        assert!(findings.iter().any(|f| f.description.contains("SIGTERM")));
    }

    #[test]
    fn negative_no_false_positives() {
        assert!(scan("let signal_to_noise = 1;\nlet unix_epoch = 0;\n").is_empty());
    }
}
