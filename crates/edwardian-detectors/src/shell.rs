use crate::util::{boundary_before, col_of, contains_word, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

pub struct ShellProcessDetector;

impl ShellProcessDetector {
    fn command_new_shell(line: &str) -> Option<(usize, &'static str)> {
        for name in ["\"sh\"", "\"bash\""] {
            if let Some(i) = line.find("Command::new(") {
                let rest = &line[i..];
                if rest.contains(name) {
                    return Some((i + 1, if name == "\"sh\"" { "sh" } else { "bash" }));
                }
            }
        }
        None
    }
}

impl Detector for ShellProcessDetector {
    fn id(&self) -> &'static str {
        "shell.process"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            if line_no == 1 && line.starts_with("#!") {
                let ev: Evidence = factory.file_scan(
                    loc(ctx.path, 1, 1),
                    format!("shebang line `{}` ties execution to a unix shell", line.trim()),
                    0.85,
                    self.id(),
                );
                accrual.add(
                    "shebang",
                    || {
                        Finding::new(
                            PlatformDependency::Shell,
                            CompatibilityState::RequiresImplementation,
                            Severity::Blocker,
                            "script with unix shebang cannot run natively on Windows",
                            Some(
                                "replace with a portable entrypoint (rust binary, node script, \
                                 or PowerShell equivalent)"
                                    .to_string(),
                            ),
                        )
                    },
                    ev,
                );
                continue;
            }

            for abs in ["/bin/sh", "/bin/bash"] {
                if let Some(col) = col_of(line, abs) {
                    let ev = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        format!("absolute unix shell path `{}`", abs),
                        0.95,
                        self.id(),
                    );
                    accrual.add(
                        "abs-shell",
                        || {
                            Finding::new(
                                PlatformDependency::Shell,
                                CompatibilityState::RequiresImplementation,
                                Severity::Blocker,
                                "invocation of an absolute unix shell path",
                                Some(
                                    "spawn a native Windows process instead, or gate behind \
                                     #[cfg(unix)] with a Windows branch"
                                        .to_string(),
                                ),
                            )
                        },
                        ev,
                    );
                }
            }

            if let Some((col, name)) = Self::command_new_shell(line) {
                let ev = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    format!("Command::new(\"{}\") spawns a unix shell", name),
                    0.9,
                    self.id(),
                );
                accrual.add(
                    "command-new-shell",
                    || {
                        Finding::new(
                            PlatformDependency::Shell,
                            CompatibilityState::RequiresImplementation,
                            Severity::Blocker,
                            "Rust code spawns `sh`/`bash` as a subprocess",
                            Some(
                                "use direct syscalls/crate APIs, or select the interpreter \
                                 per-OS via cfg(target_os)"
                                    .to_string(),
                            ),
                        )
                    },
                    ev,
                );
            }

            // Bare `bash`/`sh` invocation as a command word. Present on Windows
            // only via MSYS2/Git-Bash, so it is a Major, not a Blocker.
            for name in ["bash", "sh"] {
                let mut from = 0;
                while let Some(i) = line[from..].find(name) {
                    let idx = from + i;
                    let after = line[idx + name.len()..].chars().next();
                    let prev_char = line[..idx].chars().last();
                    let is_invocation = boundary_before(line, idx)
                        && prev_char != Some('/')
                        && prev_char != Some('.')
                        && matches!(after, Some(c) if c.is_whitespace() || c == '"' || c == '\'');
                    let not_command_new = !line[..idx].ends_with("Command::new(");
                    if is_invocation && not_command_new {
                        let col = idx + 1;
                        let ev = factory.file_scan(
                            loc(ctx.path, line_no, col),
                            format!("bare `{}` invocation", name),
                            0.8,
                            self.id(),
                        );
                        accrual.add(
                            "bare-shell",
                            || {
                                Finding::new(
                                    PlatformDependency::Shell,
                                    CompatibilityState::Adaptable,
                                    Severity::Major,
                                    "bare sh/bash invocation (no absolute path)",
                                    Some(
                                        "works under MSYS2/Git-Bash but not native Windows; \
                                         prefer a portable implementation"
                                            .to_string(),
                                    ),
                                )
                            },
                            ev,
                        );
                    }
                    from = idx + name.len();
                    if from >= line.len() {
                        break;
                    }
                }
            }

            // `git` exists on Windows too: Tooling, portable, not a blocker.
            if contains_word(line, "git") {
                let col = col_of(line, "git").unwrap_or(1);
                let ev = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    "invocation of `git`, which is available on Windows",
                    0.9,
                    self.id(),
                );
                accrual.add(
                    "git",
                    || {
                        Finding::new(
                            PlatformDependency::Tooling,
                            CompatibilityState::Portable,
                            Severity::Info,
                            "invocation of portable tool `git`",
                            None,
                        )
                    },
                    ev,
                );
            }

            if ctx.is_shell_flavored() {
                if line.contains("2>&1") || line.contains(" | ") || line.contains(">>") {
                    let col = col_of(line, "|")
                        .or_else(|| col_of(line, ">"))
                        .unwrap_or(1);
                    let ev = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        "shell pipeline/redirection syntax",
                        0.7,
                        self.id(),
                    );
                    accrual.add(
                        "pipeline",
                        || {
                            Finding::new(
                                PlatformDependency::Shell,
                                CompatibilityState::Adaptable,
                                Severity::Minor,
                                "shell pipeline/redirection in build or install script",
                                Some(
                                    "express the pipeline natively (process chaining, file APIs) \
                                     or port to PowerShell"
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

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        ShellProcessDetector.run(
            &FileContext::new(path, content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    fn by_key<'a>(findings: &'a [Finding], desc: &str) -> Option<&'a Finding> {
        findings.iter().find(|f| f.description.contains(desc))
    }

    #[test]
    fn absolute_bash_path_is_blocker() {
        let findings = scan("build.rs", "std::process::Command::new(\"/bin/bash\").arg(\"x\");");
        let f = by_key(&findings, "absolute unix shell").unwrap();
        assert_eq!(f.severity, Severity::Blocker);
        assert_eq!(f.dependency, PlatformDependency::Shell);
        assert_eq!(f.evidence.len(), 1);
    }

    #[test]
    fn command_new_sh_is_blocker() {
        let findings = scan("run.rs", "Command::new(\"sh\").arg(\"-c\").arg(\"ls\");");
        let f = by_key(&findings, "spawns `sh`/`bash`").unwrap();
        assert_eq!(f.severity, Severity::Blocker);
    }

    #[test]
    fn bare_bash_invocation_is_major_not_blocker() {
        let findings = scan("task.sh", "bash helper.sh --force\n");
        let f = by_key(&findings, "bare sh/bash invocation").unwrap();
        assert_eq!(f.severity, Severity::Major);
        assert_ne!(f.severity, Severity::Blocker);
    }

    #[test]
    fn shebang_is_flagged() {
        let findings = scan("deploy.sh", "#!/bin/bash\necho hi\n");
        let f = by_key(&findings, "shebang").unwrap();
        assert_eq!(f.severity, Severity::Blocker);
    }

    #[test]
    fn git_invocation_is_tooling_not_blocker() {
        let findings = scan("ci.sh", "git clone https://example.com/x.git\n");
        let f = by_key(&findings, "portable tool `git`").unwrap();
        assert_eq!(f.dependency, PlatformDependency::Tooling);
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn pipeline_in_shell_file_flagged_not_in_rust() {
        let sh = scan("run.sh", "cargo build 2>&1 | tee log.txt\n");
        assert!(by_key(&sh, "pipeline").is_some());
        let rs = scan("main.rs", "let x = a >> b;\n");
        assert!(by_key(&rs, "pipeline").is_none());
    }

    #[test]
    fn negative_substring_matches() {
        let findings = scan("main.rs", "use std::hash::Hash;\nlet shellfish = 1;\npush_str(\"ok\");\n");
        assert!(findings.is_empty());
    }
}
