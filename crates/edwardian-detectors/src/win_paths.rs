use crate::util::{is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

/// Windows-specific path literals (drive letters, UNC shares). When the
/// target IS Windows these are informational (correct there, but they reveal
/// a one-way platform assumption); when the target is not Windows they are
/// real portability evidence — never a Windows blocker either way.
pub struct WindowsPathDetector;

impl WindowsPathDetector {
    /// Byte column (1-based) of a drive-letter pattern `<alpha>:\` inside a
    /// string literal, if any.
    fn drive_literal_col(line: &str) -> Option<usize> {
        let b = line.as_bytes();
        let mut i = 0;
        while i + 3 < b.len() {
            if b[i].is_ascii_alphabetic() && b[i + 1] == b':' && b[i + 2] == b'\\' {
                let in_literal = i > 0 && (b[i - 1] == b'"' || b[i - 1] == b'\'');
                if in_literal {
                    return Some(i + 1);
                }
            }
            i += 1;
        }
        None
    }

    fn unc_literal_col(line: &str) -> Option<usize> {
        for needle in ["\"\\\\\\\\", "'\\\\\\\\"] {
            if let Some(i) = line.find(needle) {
                return Some(i + 2);
            }
        }
        None
    }
}

impl Detector for WindowsPathDetector {
    fn id(&self) -> &'static str {
        "fs.win-paths"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let (severity, state, description, hint) = if ctx.target == edwardian_core::Platform::Windows {
            (
                Severity::Info,
                CompatibilityState::WindowsCompatible,
                "Windows drive-letter path literal (valid on target, breaks Linux/macOS)",
                "prefer std::path over hard-coded drive letters to keep other targets working",
            )
        } else {
            (
                Severity::Major,
                CompatibilityState::Adaptable,
                "Windows drive-letter path literal is wrong on the target platform",
                "construct paths with std::path::Path; never hard-code drive letters",
            )
        };
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            if let Some(col) = Self::drive_literal_col(line) {
                let ev: Evidence = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    "drive-letter path literal (e.g. C:\\)",
                    0.9,
                    self.id(),
                );
                accrual.add(
                    "drive",
                    || {
                        Finding::new(
                            PlatformDependency::Filesystem,
                            state,
                            severity,
                            description,
                            Some(hint.to_string()),
                        )
                    },
                    ev,
                );
            }
            if let Some(col) = Self::unc_literal_col(line) {
                let ev = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    "UNC share path literal (\\\\server\\share)",
                    0.9,
                    self.id(),
                );
                accrual.add(
                    "unc",
                    || {
                        Finding::new(
                            PlatformDependency::Filesystem,
                            state,
                            severity,
                            if ctx.target == edwardian_core::Platform::Windows {
                                "UNC share path literal (valid on target, breaks Linux/macOS)"
                            } else {
                                "UNC share path literal is wrong on the target platform"
                            },
                            Some(hint.to_string()),
                        )
                    },
                    ev,
                );
            }
        }
        accrual.into_findings()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(target: Platform, content: &str) -> Vec<Finding> {
        WindowsPathDetector.run(
            &FileContext::new("main.rs", content, target),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn drive_letter_flagged_for_non_windows_target() {
        // Rust source: "C:\\Users\\x"
        let findings = scan(Platform::Linux, "let p = \"C:\\\\Users\\\\x\";");
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.state, CompatibilityState::Adaptable);
        assert_eq!(f.evidence[0].location.line, 1);
    }

    #[test]
    fn drive_letter_is_only_info_on_windows_target() {
        let findings = scan(Platform::Windows, "let p = \"D:\\\\data\";");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].state, CompatibilityState::WindowsCompatible);
    }

    #[test]
    fn unc_literal_detected() {
        // Rust source: "\\\\server\\share"
        let findings = scan(Platform::Linux, "let p = \"\\\\\\\\server\\\\share\\\\dir\";");
        assert!(findings.iter().any(|f| f.description.contains("UNC")));
    }

    #[test]
    fn negatives() {
        // colons without backslash, unquoted drive usage, single escaped backslash
        assert!(scan(Platform::Linux, "let ratio = a:b;\n").is_empty());
        assert!(scan(Platform::Linux, "cd C:\\work\n").is_empty());
        assert!(scan(Platform::Linux, "let s = \"a\\\\b\";\n").is_empty());
    }
}
