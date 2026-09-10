use crate::util::{col_of, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

pub struct EnvironmentDetector;

impl Detector for EnvironmentDetector {
    fn id(&self) -> &'static str {
        "env.unix"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            for (token, observation) in TOKENS {
                if let Some(col) = col_of(line, token) {
                    let ev: Evidence = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        *observation,
                        0.85,
                        self.id(),
                    );
                    accrual.add(
                        "env",
                        || {
                            Finding::new(
                                PlatformDependency::Configuration,
                                CompatibilityState::Configurable,
                                Severity::Minor,
                                "unix environment variable / user identity assumption",
                                Some(
                                    "read per-OS variables (APPDATA, USERPROFILE, LOCALAPPDATA) \
                                     via a platform abstraction"
                                        .to_string(),
                                ),
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

const TOKENS: &[(&str, &str)] = &[
    ("$HOME", "expansion of $HOME"),
    ("env::var(\"HOME\")", "direct read of HOME via std::env"),
    ("env::var(\"USER\")", "direct read of USER via std::env (unix-only)"),
    ("getuid", "POSIX uid/gid query"),
    ("geteuid", "POSIX uid/gid query"),
    ("/usr/bin/env", "absolute /usr/bin/env path"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(content: &str) -> Vec<Finding> {
        EnvironmentDetector.run(
            &FileContext::new("main.rs", content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn home_env_detected() {
        let findings = scan("let home = std::env::var(\"HOME\").unwrap();");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dependency, PlatformDependency::Configuration);
        assert_eq!(findings[0].severity, Severity::Minor);
    }

    #[test]
    fn shell_dollar_home_detected() {
        let findings = scan("cp x $HOME/bin\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn negative() {
        assert!(scan("let path = std::env::var(\"PATH\").unwrap();\n").is_empty());
        assert!(scan("let homeward = 1;\n").is_empty());
    }
}
