use crate::util::{cols_of, in_string_literal, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{
    CompatibilityState, Evidence, Finding, PlatformDependency, Severity,
};
use edwardian_evidence::EvidenceFactory;

const POSIX_ROOTS: &[&str] = &[
    "/home/", "/etc/", "/usr/", "/var/", "/tmp/", "/dev/", "/proc/", "/sys/",
];

pub struct FilesystemDetector;

impl Detector for FilesystemDetector {
    fn id(&self) -> &'static str {
        "fs.posix-paths"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            for root in POSIX_ROOTS {
                if let Some(col) = in_string_literal(line, root) {
                    let ev: Evidence = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        format!("string literal references POSIX root `{}`", root),
                        0.9,
                        self.id(),
                    );
                    accrual.add(
                        "posix-root",
                        || {
                            Finding::new(
                                PlatformDependency::Filesystem,
                                CompatibilityState::Replaceable,
                                Severity::Major,
                                format!("hard-coded POSIX absolute path ({}...)", root),
                                Some(
                                    "derive the path from configuration or use \
                                     platform-appropriate directories (e.g. %APPDATA%, %ProgramData%)"
                                        .to_string(),
                                ),
                            )
                        },
                        ev,
                    );
                }
            }
            let bare_slash = in_string_literal(line, "/");
            let slash_join = bare_slash.is_some()
                && (line.contains("format!") || line.contains("concat!") || line.contains("push_str"));
            if slash_join {
                let col = bare_slash.unwrap_or(1);
                let ev = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    "unix path separator baked into a formatted string literal",
                    0.7,
                    self.id(),
                );
                accrual.add(
                    "unix-join",
                    || {
                        Finding::new(
                            PlatformDependency::Filesystem,
                            CompatibilityState::Adaptable,
                            Severity::Minor,
                            "unix-style path join in string literal",
                            Some("use std::path::Path::join or std::path::MAIN_SEPARATOR".to_string()),
                        )
                    },
                    ev,
                );
            }
            // String literals like "{}/config.toml" that assume '/' separators.
            if line.contains("\"{/") || line.contains("'{/") || line.contains("\"{}/") {
                let col = cols_of(line, "{/").first().copied().unwrap_or(1);
                let ev = factory.file_scan(
                    loc(ctx.path, line_no, col),
                    "format placeholder joined to a `/` separator literal",
                    0.75,
                    self.id(),
                );
                accrual.add(
                    "unix-join",
                    || {
                        Finding::new(
                            PlatformDependency::Filesystem,
                            CompatibilityState::Adaptable,
                            Severity::Minor,
                            "unix-style path join in string literal",
                            Some("use std::path::Path::join or std::path::MAIN_SEPARATOR".to_string()),
                        )
                    },
                    ev,
                );
            }
        }
        accrual.into_findings()
    }
}

/// Inventory-level check: two files in one directory whose names differ only
/// by case. On case-insensitive target filesystems (Windows, macOS default)
/// one file shadows the other — a silent build/runtime hazard. Emits one
/// finding per directory at the directory location.
pub fn case_collision_findings(
    paths: &[String],
    target: edwardian_core::Platform,
    factory: &mut edwardian_evidence::EvidenceFactory,
) -> Vec<Finding> {
    use edwardian_core::{Evidence, EvidenceSource, Platform, PlatformDependency};
    use std::collections::BTreeMap;

    let mut by_dir: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for p in paths {
        let (dir, name) = match p.rfind('/') {
            Some(i) => (p[..i].to_string(), p[i + 1..].to_string()),
            None => (".".to_string(), p.clone()),
        };
        by_dir
            .entry((dir, name.to_lowercase()))
            .or_default()
            .push(name);
    }
    let (severity, state) = match target {
        Platform::Windows | Platform::MacOs => (Severity::Major, CompatibilityState::Configurable),
        _ => (Severity::Minor, CompatibilityState::Configurable),
    };
    let mut out = Vec::new();
    for ((dir, _lower), mut names) in by_dir {
        names.sort();
        names.dedup();
        if names.len() < 2 {
            continue;
        }
        let id = factory.ids().next_evidence_id();
        let mut f = Finding::new(
            PlatformDependency::Filesystem,
            state,
            severity,
            format!(
                "case-insensitive filename collision in `{}`: {}",
                dir,
                names.join(" vs ")
            ),
            Some("rename one of the files; case-insensitive targets shadow one of them".to_string()),
        );
        f.evidence.push(Evidence {
            id,
            source: EvidenceSource::RepoLayout,
            location: loc(&dir, 1, 1),
            observation: format!("directory `{}` holds case-colliding files: {}", dir, names.join(", ")),
            confidence: 1.0,
            detector: "fs.case".to_string(),
        });
        out.push(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        FilesystemDetector.run(
            &FileContext::new(path, content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn detects_hardcoded_etc_path() {
        let findings = scan("cfg.rs", "let conf = \"/etc/myapp/config.toml\";");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.dependency, PlatformDependency::Filesystem);
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.evidence[0].location.line, 1);
        assert!(f.evidence[0].location.column > 1);
    }

    #[test]
    fn detects_home_and_var() {
        let content = "let a = \"/home/user/x\";\nlet b = \"/var/log/y\";\n";
        let findings = scan("main.rs", content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn ignores_comments_and_non_literals() {
        let content = "// let p = \"/etc/x\";\nlet q = prefix.join(\"etc/x\");\n";
        let findings = scan("main.rs", content);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_unix_join_literal() {
        let findings = scan("main.rs", "let p = format!(\"{}/logs/app.log\", base);");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Minor);
    }

    #[test]
    fn case_collision_finds_shadowed_pairs() {
        use edwardian_core::Platform;
        let paths: Vec<String> = ["src/Config.rs", "src/config.rs", "src/main.rs", "README.md"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut factory = EvidenceFactory::new();
        let findings = case_collision_findings(&paths, Platform::Windows, &mut factory);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.description.contains("Config.rs vs config.rs"));
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.evidence[0].location.path, "src");
        assert_eq!(f.evidence[0].id, "EWD-00001");
        // No collision -> no finding; non-case-insensitive target downgrades severity.
        let clean: Vec<String> = ["a.rs", "b.rs"].iter().map(|s| s.to_string()).collect();
        assert!(case_collision_findings(&clean, Platform::Windows, &mut factory).is_empty());
        let findings = case_collision_findings(&paths, Platform::Linux, &mut factory);
        assert_eq!(findings[0].severity, Severity::Minor);
    }

    #[test]
    fn negative_windows_path_and_plain_slash() {
        let content = "let p = \"C:\\\\Users\\\\x\";\nlet q = \"/\";\nlet r = base.join(\"logs\");\n";
        assert!(scan("main.rs", content).is_empty());
    }
}
