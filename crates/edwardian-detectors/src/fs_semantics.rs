use crate::util::{col_of, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

/// Unix filesystem-semantics dependence: symlink creation/traversal and the
/// executable-bit/permission model. None of this maps cleanly onto stock
/// Windows (symlinks need privilege/development mode; there is no st_mode).
pub struct FilesystemSemanticsDetector;

impl Detector for FilesystemSemanticsDetector {
    fn id(&self) -> &'static str {
        "fs.semantics"
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
        token: "std::os::unix::fs::symlink",
        key: "symlink",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "symlink creation via unix-only API (`std::os::unix::fs::symlink`)",
        hint: "gate behind cfg(unix) and provide a Windows branch (std::os::windows::fs::symlink_file/dir), or avoid symlinks",
        confidence: 0.95,
    },
    Rule {
        token: "os.symlink",
        key: "symlink",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "symlink creation (`os.symlink`)",
        hint: "requires elevated privileges/development mode on Windows; prefer directory junctions or explicit copies",
        confidence: 0.9,
    },
    Rule {
        token: "symlink(",
        key: "symlink",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "symlink creation or reliance (`symlink(...)`)",
        hint: "symlinks are a restricted operation on Windows; abstract behind an fs trait",
        confidence: 0.8,
    },
    Rule {
        token: "ln -s",
        key: "symlink",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "symlink creation in script (`ln -s`)",
        hint: "no native equivalent without privileges; rework the install step for Windows",
        confidence: 0.9,
    },
    Rule {
        token: "PermissionsExt",
        key: "exec-bit",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "unix permission model (`PermissionsExt`)",
        hint: "Windows has no st_mode; map to ACLs or drop the permission step on Windows",
        confidence: 0.95,
    },
    Rule {
        token: "chmod",
        key: "exec-bit",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "unix permission model (`chmod`)",
        hint: "map to icacls/ACL operations or cfg-gate the permission step",
        confidence: 0.9,
    },
    Rule {
        token: "0o755",
        key: "mode-literal",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "unix mode literal (`0o755`)",
        hint: "mode bits have no Windows equivalent; cfg-gate set_permissions calls",
        confidence: 0.85,
    },
    Rule {
        token: "0o644",
        key: "mode-literal",
        dependency: PlatformDependency::Filesystem,
        state: CompatibilityState::RequiresImplementation,
        severity: Severity::Major,
        description: "unix mode literal (`0o644`)",
        hint: "mode bits have no Windows equivalent; cfg-gate set_permissions calls",
        confidence: 0.85,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        FilesystemSemanticsDetector.run(
            &FileContext::new(path, content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn unix_symlink_api_is_major() {
        let findings = scan("main.rs", "std::os::unix::fs::symlink(a, b)?;");
        let f = findings.iter().find(|f| f.description.contains("symlink")).unwrap();
        assert_eq!(f.dependency, PlatformDependency::Filesystem);
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.state, CompatibilityState::Replaceable);
    }

    #[test]
    fn ln_dash_s_in_script_detected() {
        let findings = scan("install.sh", "ln -s /usr/bin/tool /usr/local/bin/tool\n");
        assert!(findings.iter().any(|f| f.description.contains("ln -s")));
    }

    #[test]
    fn permissions_ext_and_mode_literals_detected() {
        let content = "use std::os::unix::fs::PermissionsExt;\n\
                       std::fs::set_permissions(p, perms.mode(0o755))?;\n";
        let findings = scan("main.rs", content);
        assert!(findings.iter().any(|f| f.description.contains("PermissionsExt")));
        assert!(findings.iter().any(|f| f.description.contains("0o755")));
        assert!(findings.iter().all(|f| f.severity == Severity::Major));
    }

    #[test]
    fn negatives_no_false_positives() {
        let content = "let hardlink_count = 1;\nlet mode_of_transport = \"car\";\nlet x = 0x755;\n";
        assert!(scan("main.rs", content).is_empty());
    }
}
