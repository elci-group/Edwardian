use edwardian_core::{
    Alternative, DecisionStrategy, Finding, Maturity, Platform, PlatformDependency,
};

/// Resolve a finding to a capability key looked up in the seed registry.
/// Returns `None` for findings that need no alternative (e.g. portable tools).
pub fn capability_key(finding: &Finding) -> Option<&'static str> {
    let desc = finding.description.as_str();
    match finding.dependency {
        PlatformDependency::Shell => {
            if desc.contains("absolute unix shell") || desc.contains("spawns") {
                Some("process:spawn-shell")
            } else if desc.contains("shebang") || desc.contains("pipeline") {
                Some("script:entrypoint")
            } else {
                Some("shell:interpreter")
            }
        }
        PlatformDependency::Service => {
            if desc.contains("systemd") {
                Some("service:manager")
            } else if desc.contains("cron") {
                Some("service:scheduler")
            } else {
                Some("service:manager")
            }
        }
        PlatformDependency::Kernel if desc.contains("inotify") => Some("fs:watch"),
        PlatformDependency::Kernel => Some("kernel:device-events"),
        PlatformDependency::IPC if desc.contains("D-Bus") => Some("ipc:bus"),
        PlatformDependency::IPC => Some("ipc:local-socket"),
        PlatformDependency::Process => Some("process:signals"),
        PlatformDependency::Filesystem => Some("fs:portable-paths"),
        PlatformDependency::Tooling if desc.contains("pkg-config") => Some("tooling:pkg-config"),
        PlatformDependency::Tooling if desc.contains("git") => None,
        PlatformDependency::Tooling => Some("tooling:compiler-abi"),
        PlatformDependency::BuildSystem if desc.contains("Makefile") => Some("build:make"),
        PlatformDependency::BuildSystem if desc.contains("Meson") => Some("build:meson"),
        PlatformDependency::CI => None,
        PlatformDependency::Configuration => Some("env:dirs"),
        PlatformDependency::Compiler => Some("tooling:compiler-abi"),
        _ => None,
    }
}

/// In-code seed table: capability -> candidate alternatives. Each alternative
/// records *why it fits*; "runs on Windows" alone is never the justification.
pub fn seed_registry() -> Vec<(&'static str, Vec<Alternative>)> {
    use DecisionStrategy::*;
    use Maturity::*;
    use Platform::*;
    vec![
        (
            "shell:interpreter",
            vec![
                Alternative::new(
                    "PowerShell (pwsh)",
                    "shell scripting",
                    vec![Windows, Linux, MacOs],
                    "MIT",
                    Stable,
                    3,
                    2,
                    ExistingWindowsCompatible,
                    "native Windows shell; POSIX scripts can be ported mechanically",
                ),
                Alternative::new(
                    "MSYS2 bash",
                    "shell scripting",
                    vec![Windows],
                    "GPL-3.0",
                    Stable,
                    1,
                    4,
                    ThinAdapter,
                    "keeps bash scripts running, but adds a runtime dependency and \
                     path-translation pitfalls; an adapter, not a port",
                ),
                Alternative::new(
                    "native Rust implementation",
                    "shell scripting",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Stable,
                    4,
                    1,
                    InHouseReplacement,
                    "removes the interpreter dependency entirely; highest long-term value",
                ),
            ],
        ),
        (
            "process:spawn-shell",
            vec![
                Alternative::new(
                    "direct API / crate call",
                    "subprocess shell-out",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Stable,
                    3,
                    1,
                    ExistingPortable,
                    "most shell-outs wrap functionality available as a portable library call",
                ),
                Alternative::new(
                    "cmd.exe / PowerShell with per-OS selection",
                    "subprocess shell-out",
                    vec![Windows],
                    "MIT",
                    Stable,
                    2,
                    3,
                    NativeBackend,
                    "native Windows process spawning via std::process with cfg(target_os)",
                ),
            ],
        ),
        (
            "script:entrypoint",
            vec![
                Alternative::new(
                    "compiled Rust binary entrypoint",
                    "build/install entrypoint",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Stable,
                    3,
                    1,
                    InHouseReplacement,
                    "one portable entrypoint replaces N shell scripts",
                ),
                Alternative::new(
                    "PowerShell entrypoint scripts",
                    "build/install entrypoint",
                    vec![Windows],
                    "MIT",
                    Stable,
                    2,
                    2,
                    NativeBackend,
                    "idiomatic on Windows; keep per-OS script pairs behind a thin driver",
                ),
            ],
        ),
        (
            "service:manager",
            vec![
                Alternative::new(
                    "service-manager crate (Windows SCM)",
                    "service lifecycle",
                    vec![Windows],
                    "MIT OR Apache-2.0",
                    Stable,
                    2,
                    2,
                    FossSubstitution,
                    "mature FOSS crate wrapping the Service Control Manager; maps 1:1 to \
                     systemd unit semantics",
                ),
                Alternative::new(
                    "Windows Task Scheduler",
                    "service lifecycle",
                    vec![Windows],
                    "proprietary (OS built-in)",
                    Stable,
                    2,
                    3,
                    NativeBackend,
                    "no service registration needed; weaker supervision semantics than SCM",
                ),
            ],
        ),
        (
            "service:scheduler",
            vec![
                Alternative::new(
                    "Windows Task Scheduler (schtasks / windows crate)",
                    "job scheduling",
                    vec![Windows],
                    "proprietary (OS built-in)",
                    Stable,
                    2,
                    2,
                    NativeBackend,
                    "direct equivalent of cron with time/event triggers",
                ),
                Alternative::new(
                    "tokio-cron-scheduler (in-process)",
                    "job scheduling",
                    vec![Windows, Linux, MacOs],
                    "MIT OR Apache-2.0",
                    Stable,
                    2,
                    3,
                    FossSubstitution,
                    "portable when the scheduler can live inside the daemon process itself",
                ),
            ],
        ),
        (
            "fs:watch",
            vec![
                Alternative::new(
                    "notify crate",
                    "filesystem watching",
                    vec![Windows, Linux, MacOs],
                    "CC0-1.0",
                    Stable,
                    1,
                    1,
                    FossSubstitution,
                    "de-facto standard abstraction over inotify/ReadDirectoryChangesW/FSEvents; \
                     the obvious drop-in",
                ),
                Alternative::new(
                    "custom Watcher trait + per-OS backends",
                    "filesystem watching",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Beta,
                    5,
                    2,
                    ArchitecturalRedesign,
                    "only when notify's event semantics are insufficient; full control over \
                     debounce/recursive-watch behaviour",
                ),
            ],
        ),
        (
            "ipc:local-socket",
            vec![
                Alternative::new(
                    "named pipes (std/CreateNamedPipe)",
                    "local IPC transport",
                    vec![Windows],
                    "proprietary (OS built-in)",
                    Stable,
                    2,
                    2,
                    NativeBackend,
                    "canonical Windows local IPC with equivalent streaming semantics to \
                     unix sockets",
                ),
                Alternative::new(
                    "interprocess crate",
                    "local IPC transport",
                    vec![Windows, Linux, MacOs],
                    "MIT OR Apache-2.0",
                    Stable,
                    1,
                    1,
                    FossSubstitution,
                    "portable local-socket + named-pipe API from one dependency",
                ),
            ],
        ),
        (
            "ipc:bus",
            vec![
                Alternative::new(
                    "local gRPC/HTTP loopback",
                    "system IPC bus",
                    vec![Windows, Linux, MacOs],
                    "Apache-2.0",
                    Stable,
                    3,
                    2,
                    FossSubstitution,
                    "replaces D-Bus signalling with a well-supported portable stack",
                ),
                Alternative::new(
                    "COM/RPC redesign",
                    "system IPC bus",
                    vec![Windows],
                    "proprietary (OS built-in)",
                    Stable,
                    5,
                    4,
                    ArchitecturalRedesign,
                    "deepest Windows integration; justified only for OS-level service contracts",
                ),
            ],
        ),
        (
            "process:signals",
            vec![
                Alternative::new(
                    "CTRL_C_EVENT / CTRL_CLOSE_EVENT handlers",
                    "graceful shutdown signalling",
                    vec![Windows],
                    "proprietary (OS built-in)",
                    Stable,
                    2,
                    2,
                    NativeBackend,
                    "console control handlers are the Windows equivalent of SIGINT/SIGTERM",
                ),
                Alternative::new(
                    "graceful-shutdown channel (in-process)",
                    "graceful shutdown signalling",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Stable,
                    2,
                    1,
                    ExistingPortable,
                    "a shutdown broadcast channel removes the OS signal dependency where \
                     signalling is internal",
                ),
            ],
        ),
        (
            "fs:portable-paths",
            vec![
                Alternative::new(
                    "std::path::PathBuf + directories crate",
                    "path handling",
                    vec![Windows, Linux, MacOs],
                    "MIT OR Apache-2.0",
                    Stable,
                    1,
                    1,
                    ExistingPortable,
                    "pure-Rust path handling already portable; only hard-coded literals \
                     need replacing",
                ),
            ],
        ),
        (
            "tooling:pkg-config",
            vec![
                Alternative::new(
                    "vcpkg",
                    "native library discovery",
                    vec![Windows, Linux, MacOs],
                    "MIT",
                    Stable,
                    2,
                    2,
                    FossSubstitution,
                    "first-class cargo integration (`vcpkg` build helper) and the standard \
                     native dependency source on Windows",
                ),
                Alternative::new(
                    "MSYS2 pkgconf",
                    "native library discovery",
                    vec![Windows],
                    "GPL-2.0",
                    Stable,
                    1,
                    4,
                    ThinAdapter,
                    "keeps pkg-config workflows alive but ties the build to the MSYS2 \
                     environment",
                ),
            ],
        ),
        (
            "build:make",
            vec![
                Alternative::new(
                    "cargo build (native)",
                    "build orchestration",
                    vec![Windows, Linux, MacOs],
                    "MIT OR Apache-2.0",
                    Stable,
                    2,
                    1,
                    ExistingPortable,
                    "the project is Rust-first; cargo already does what the Makefile wraps",
                ),
                Alternative::new(
                    "cargo-make",
                    "build orchestration",
                    vec![Windows, Linux, MacOs],
                    "Apache-2.0",
                    Stable,
                    1,
                    2,
                    FossSubstitution,
                    "portable make-like task runner when Makefile logic must survive verbatim",
                ),
            ],
        ),
        (
            "build:meson",
            vec![
                Alternative::new(
                    "cmake (Windows-supported)",
                    "C/C++ build system",
                    vec![Windows, Linux, MacOs],
                    "BSD-3-Clause",
                    Stable,
                    3,
                    2,
                    FossSubstitution,
                    "cmake has first-class Visual Studio/MSVC generators; meson does not",
                ),
            ],
        ),
        (
            "env:dirs",
            vec![
                Alternative::new(
                    "directories crate",
                    "user/system directory resolution",
                    vec![Windows, Linux, MacOs],
                    "MIT OR Apache-2.0",
                    Stable,
                    1,
                    1,
                    FossSubstitution,
                    "resolves config/cache/data dirs per-OS (APPDATA, ~/.config) from one API",
                ),
                Alternative::new(
                    "cfg(target_os) env var table",
                    "user/system directory resolution",
                    vec![Windows, Linux, MacOs],
                    "project license",
                    Stable,
                    2,
                    1,
                    ConfigurationChange,
                    "small hand-rolled mapping when adding a dependency is undesirable",
                ),
            ],
        ),
        (
            "kernel:device-events",
            vec![
                Alternative::new(
                    "windows crate (WMI/SetupAPI)",
                    "device event subscription",
                    vec![Windows],
                    "MIT OR Apache-2.0",
                    Stable,
                    3,
                    3,
                    NativeBackend,
                    "WMI instance events and cfgmgr32 notifications cover udev's role",
                ),
            ],
        ),
        (
            "tooling:compiler-abi",
            vec![
                Alternative::new(
                    "MSVC toolchain (windows-msvc target)",
                    "C toolchain",
                    vec![Windows],
                    "proprietary (Visual Studio)",
                    Stable,
                    2,
                    2,
                    NativeBackend,
                    "the supported ABI for Windows Rust targets; GNU target is a fallback",
                ),
            ],
        ),
    ]
}

pub struct AlternativeRegistry {
    table: Vec<(&'static str, Vec<Alternative>)>,
}

impl AlternativeRegistry {
    pub fn seeded() -> Self {
        AlternativeRegistry {
            table: seed_registry(),
        }
    }

    /// Alternatives for a capability, ordered by the decision hierarchy:
    /// existing portable → existing Windows-compatible → configuration change →
    /// FOSS substitution → thin adapter → native backend → in-house replacement →
    /// architectural redesign.
    pub fn alternatives_for(&self, capability: &str) -> Vec<Alternative> {
        let mut alts: Vec<Alternative> = self
            .table
            .iter()
            .find(|(cap, _)| *cap == capability)
            .map(|(_, a)| a.clone())
            .unwrap_or_default();
        alts.sort_by_key(|a| a.strategy.rank());
        alts
    }

    pub fn capabilities(&self) -> Vec<&'static str> {
        self.table.iter().map(|(c, _)| *c).collect()
    }
}

pub fn decision_hierarchy() -> Vec<DecisionStrategy> {
    [
        DecisionStrategy::ExistingPortable,
        DecisionStrategy::ExistingWindowsCompatible,
        DecisionStrategy::ConfigurationChange,
        DecisionStrategy::FossSubstitution,
        DecisionStrategy::ThinAdapter,
        DecisionStrategy::NativeBackend,
        DecisionStrategy::InHouseReplacement,
        DecisionStrategy::ArchitecturalRedesign,
    ]
    .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_ordered_by_decision_hierarchy() {
        let reg = AlternativeRegistry::seeded();
        for cap in reg.capabilities() {
            let alts = reg.alternatives_for(cap);
            let mut ranks = alts.iter().map(|a| a.strategy.rank()).collect::<Vec<_>>();
            let sorted = ranks.clone();
            ranks.sort();
            assert_eq!(ranks, sorted, "capability {} out of order", cap);
        }
    }

    #[test]
    fn fs_watch_prefers_notify_crate() {
        let reg = AlternativeRegistry::seeded();
        let alts = reg.alternatives_for("fs:watch");
        assert_eq!(alts[0].name, "notify crate");
        assert!(alts[0].platforms.contains(&Platform::Windows));
        assert!(alts.iter().any(|a| a.strategy == DecisionStrategy::ArchitecturalRedesign));
    }

    #[test]
    fn portable_toolings_have_no_alternatives() {
        let mut f = Finding::new(
            PlatformDependency::Tooling,
            edwardian_core::CompatibilityState::Portable,
            edwardian_core::Severity::Info,
            "invocation of portable tool `git`",
            None,
        );
        assert!(capability_key(&f).is_none());
        f.description = "pkg-config native library discovery".to_string();
        assert_eq!(capability_key(&f), Some("tooling:pkg-config"));
    }
}
