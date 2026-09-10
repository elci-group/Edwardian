use crate::util::{col_of, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

pub struct BuildSystemDetector;

impl Detector for BuildSystemDetector {
    fn id(&self) -> &'static str {
        "build.unix"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        let base = ctx.basename();

        let filename_rules: &[(&str, &str, PlatformDependency, CompatibilityState, Severity, &str, &str)] = &[
            ("Makefile", "make", PlatformDependency::BuildSystem, CompatibilityState::Replaceable, Severity::Major,
             "Makefile-driven build", "prefer cargo build; drive remaining native steps via cmake/ninja which support Windows"),
            ("makefile", "make", PlatformDependency::BuildSystem, CompatibilityState::Replaceable, Severity::Major,
             "Makefile-driven build", "prefer cargo build; drive remaining native steps via cmake/ninja which support Windows"),
            ("meson.build", "meson", PlatformDependency::BuildSystem, CompatibilityState::Replaceable, Severity::Major,
             "Meson build system", "port to cargo or cmake; meson has limited Windows support"),
            ("CMakeLists.txt", "cmake", PlatformDependency::BuildSystem, CompatibilityState::Configurable, Severity::Minor,
             "CMake build (supports Windows)", "no change required; ensure CI uses a Windows cmake generator"),
            (".gitlab-ci.yml", "gitlab-ci", PlatformDependency::CI, CompatibilityState::Configurable, Severity::Minor,
             "GitLab CI configuration", "add a Windows runner/tag or a GitHub Actions windows matrix"),
            ("build.rs", "build-rs", PlatformDependency::BuildSystem, CompatibilityState::Configurable, Severity::Info,
             "Cargo build script present", "keep portable: avoid shelling out to unix tools inside build.rs"),
        ];
        for (name, key, dep, state, sev, desc, hint) in filename_rules {
            if base == *name {
                let ev: Evidence = factory.file_scan(
                    loc(ctx.path, 1, 1),
                    format!("file `{}` present in repository", name),
                    0.95,
                    self.id(),
                );
                accrual.add(
                    key,
                    || Finding::new(*dep, *state, *sev, *desc, Some(hint.to_string())),
                    ev,
                );
            }
        }

        if ctx.path.contains(".github/workflows/") || ctx.path.contains(".github\\workflows\\") {
            let ev = factory.file_scan(
                loc(ctx.path, 1, 1),
                "GitHub Actions workflow file",
                0.9,
                self.id(),
            );
            accrual.add(
                "gha",
                || {
                    Finding::new(
                        PlatformDependency::CI,
                        CompatibilityState::Configurable,
                        Severity::Minor,
                        "GitHub Actions CI (Linux-only unless a windows matrix exists)",
                        Some("extend the matrix with `os: [windows-latest]`".to_string()),
                    )
                },
                ev,
            );
        }

        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            for rule in CONTENT_RULES {
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

const CONTENT_RULES: &[Rule] = &[
    Rule {
        token: "pkg-config",
        key: "pkg-config",
        dependency: PlatformDependency::Tooling,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "pkg-config native library discovery",
        hint: "use vcpkg, or emit cargo link directives from a build script on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "pkg_config",
        key: "pkg-config",
        dependency: PlatformDependency::Tooling,
        state: CompatibilityState::Replaceable,
        severity: Severity::Major,
        description: "pkg-config native library discovery (pkg_config crate)",
        hint: "use vcpkg, or emit cargo link directives from a build script on Windows",
        confidence: 0.9,
    },
    Rule {
        token: "bindgen",
        key: "bindgen",
        dependency: PlatformDependency::Tooling,
        state: CompatibilityState::Adaptable,
        severity: Severity::Minor,
        description: "bindgen (requires libclang on the build host)",
        hint: "works on Windows with LLVM installed; pin the libclang dependency in CI",
        confidence: 0.8,
    },
    Rule {
        token: "cc =",
        key: "cc-crate",
        dependency: PlatformDependency::Tooling,
        state: CompatibilityState::Adaptable,
        severity: Severity::Minor,
        description: "`cc` crate compiles C/C++ with a platform toolchain",
        hint: "ensure a MSVC toolchain is present on Windows builders",
        confidence: 0.75,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(path: &str, content: &str) -> Vec<Finding> {
        BuildSystemDetector.run(
            &FileContext::new(path, content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn makefile_presence_flagged() {
        let findings = scan("Makefile", "all:\n\tcargo build\n");
        let f = &findings[0];
        assert_eq!(f.dependency, PlatformDependency::BuildSystem);
        assert_eq!(f.severity, Severity::Major);
        assert_eq!(f.evidence[0].location.line, 1);
    }

    #[test]
    fn cmake_is_only_minor() {
        let findings = scan("CMakeLists.txt", "cmake_minimum_required(VERSION 3.20)\n");
        assert_eq!(findings[0].severity, Severity::Minor);
    }

    #[test]
    fn github_workflow_flagged_as_ci() {
        let findings = scan(".github/workflows/ci.yml", "on: [push]\n");
        assert_eq!(findings[0].dependency, PlatformDependency::CI);
        assert_eq!(findings[0].state, CompatibilityState::Configurable);
    }

    #[test]
    fn pkg_config_content_flagged() {
        let findings = scan("build.rs", "println!(\"cargo:rustc-link-lib=z\"); // pkg-config style\n");
        let f = findings.iter().find(|f| f.description.contains("pkg-config")).unwrap();
        assert_eq!(f.severity, Severity::Major);
    }

    #[test]
    fn plain_cargo_toml_clean() {
        assert!(scan("Cargo.toml", "[package]\nname = \"x\"\nversion = \"0.1.0\"\n").is_empty());
    }
}
