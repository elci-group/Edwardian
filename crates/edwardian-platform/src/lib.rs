use edwardian_core::Platform;
use serde::{Deserialize, Serialize};

/// Static knowledge about a target platform that the pipeline reasons with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformProfile {
    pub platform: Platform,
    pub shell: Option<&'static str>,
    pub default_shell: Option<&'static str>,
    pub path_separator: char,
    pub supports_unix_sockets: bool,
    pub supports_posix_signals: bool,
    pub service_manager: Option<&'static str>,
    pub fs_watch_api: Option<&'static str>,
    pub package_managers: Vec<&'static str>,
    pub native_abi: &'static str,
}

pub fn profile_for(platform: Platform) -> PlatformProfile {
    match platform {
        Platform::Linux => PlatformProfile {
            platform,
            shell: Some("POSIX sh family (bash, dash, zsh)"),
            default_shell: Some("/bin/sh"),
            path_separator: '/',
            supports_unix_sockets: true,
            supports_posix_signals: true,
            service_manager: Some("systemd"),
            fs_watch_api: Some("inotify"),
            package_managers: vec!["apt", "dnf", "pacman"],
            native_abi: "ELF / System V AMD64",
        },
        Platform::Windows => PlatformProfile {
            platform,
            shell: Some("cmd.exe / PowerShell"),
            default_shell: Some("cmd.exe"),
            path_separator: '\\',
            supports_unix_sockets: false,
            supports_posix_signals: false,
            service_manager: Some("Windows Service Control Manager"),
            fs_watch_api: Some("ReadDirectoryChangesW"),
            package_managers: vec!["winget", "vcpkg", "scoop"],
            native_abi: "PE / MSVC x64",
        },
        Platform::MacOs => PlatformProfile {
            platform,
            shell: Some("POSIX sh family (zsh)"),
            default_shell: Some("/bin/zsh"),
            path_separator: '/',
            supports_unix_sockets: true,
            supports_posix_signals: true,
            service_manager: Some("launchd"),
            fs_watch_api: Some("FSEvents / kqueue"),
            package_managers: vec!["homebrew"],
            native_abi: "Mach-O",
        },
        Platform::FreeBsd | Platform::OpenBsd => PlatformProfile {
            platform,
            shell: Some("POSIX sh family"),
            default_shell: Some("/bin/sh"),
            path_separator: '/',
            supports_unix_sockets: true,
            supports_posix_signals: true,
            service_manager: Some("rc.d"),
            fs_watch_api: Some("kqueue"),
            package_managers: vec!["pkg"],
            native_abi: "ELF",
        },
        Platform::Android => PlatformProfile {
            platform,
            shell: Some("toybox/sh"),
            default_shell: Some("/system/bin/sh"),
            path_separator: '/',
            supports_unix_sockets: true,
            supports_posix_signals: true,
            service_manager: Some("init (Android init)"),
            fs_watch_api: Some("inotify"),
            package_managers: vec!["apk"],
            native_abi: "ELF / Bionic",
        },
        Platform::Ios => PlatformProfile {
            platform,
            shell: None,
            default_shell: None,
            path_separator: '/',
            supports_unix_sockets: true,
            supports_posix_signals: true,
            service_manager: None,
            fs_watch_api: Some("FSEvents / kqueue"),
            package_managers: vec![],
            native_abi: "Mach-O",
        },
        Platform::Wasm => PlatformProfile {
            platform,
            shell: None,
            default_shell: None,
            path_separator: '/',
            supports_unix_sockets: false,
            supports_posix_signals: false,
            service_manager: None,
            fs_watch_api: Some("WASI preview filesystem events (limited)"),
            package_managers: vec![],
            native_abi: "WASM32",
        },
    }
}

pub fn all_profiles() -> Vec<PlatformProfile> {
    [
        Platform::Linux,
        Platform::Windows,
        Platform::MacOs,
        Platform::FreeBsd,
        Platform::OpenBsd,
        Platform::Android,
        Platform::Ios,
        Platform::Wasm,
    ]
    .into_iter()
    .map(profile_for)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_profile_has_no_posix_facilities() {
        let p = profile_for(Platform::Windows);
        assert!(!p.supports_unix_sockets);
        assert!(!p.supports_posix_signals);
        assert_eq!(p.path_separator, '\\');
        assert_eq!(p.fs_watch_api, Some("ReadDirectoryChangesW"));
    }

    #[test]
    fn every_platform_has_a_profile() {
        assert_eq!(all_profiles().len(), 8);
    }
}
