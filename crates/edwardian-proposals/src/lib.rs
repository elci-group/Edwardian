use edwardian_core::{Finding, ImplementationState, PlatformDependency, Proposal};

/// Capabilities where no drop-in FOSS alternative is considered sufficient
/// and a purpose-built design is proposed instead.
const PROPOSAL_CAPABILITIES: &[&str] = &["fs-watch"];

/// Turn findings that represent architectural gaps into capability proposals
/// (EWP-NNN). Currently: Linux inotify-style filesystem watching.
pub fn generate_proposals(findings: &[Finding]) -> Vec<Proposal> {
    let mut proposals = Vec::new();
    let wants_fs_watch = findings.iter().any(|f| {
        f.dependency == PlatformDependency::Kernel && f.description.contains("inotify")
    });
    if wants_fs_watch {
        proposals.push(fs_watch_proposal(proposals.len() + 1));
    }
    proposals
}

fn fs_watch_proposal(n: usize) -> Proposal {
    Proposal {
        id: format!("EWP-{:03}", n),
        capability: "fs-watch".to_string(),
        current_impl: "Linux inotify (raw fd watch set, manual event debounce)".to_string(),
        required_impl: "Backend abstraction over inotify (Linux) and ReadDirectoryChangesW (Windows)"
            .to_string(),
        recommended_architecture: "Rust `FileWatcher` trait in the host crate with per-OS \
                                   backends (`InotifyBackend`, `RdcwBackend`) selected at \
                                   compile time via cfg(target_os); events normalised into a \
                                   single platform-neutral enum"
            .to_string(),
        required_interface: "pub trait FileWatcher { fn watch(&mut self, path: &Path, recursive: bool) -> Result<WatchId>; fn events(&mut self) -> Result<Vec<WatchEvent>>; }"
            .to_string(),
        compatibility_invariant: "Every event sequence producible on Linux inotify must be \
                                  representable on the Windows backend (create/delete/modify/rename \
                                  with before/after paths); no event type may be silently dropped — \
                                  unrepresentable events map to a documented `Other` variant"
            .to_string(),
        estimated_effort_days: 8,
        risk: "Rename event pairing differs between inotify and ReadDirectoryChangesW; recursive \
               watch semantics and symlink behaviour need explicit tests to keep the invariant"
            .to_string(),
        state: ImplementationState::Analysed,
    }
}

pub fn proposal_supported(capability: &str) -> bool {
    PROPOSAL_CAPABILITIES.contains(&capability)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::{CompatibilityState, Severity};

    #[test]
    fn inotify_finding_yields_fs_watch_proposal() {
        let mut f = Finding::new(
            PlatformDependency::Kernel,
            CompatibilityState::RequiresImplementation,
            Severity::Major,
            "Linux inotify filesystem-watch dependency",
            None,
        );
        f.evidence.push(edwardian_core::Evidence::file_scan(
            "EWD-00001",
            edwardian_core::Location::new("src/watch.rs", 1, 1),
            "inotify usage",
            0.9,
            "ipc.unix",
        ));
        let proposals = generate_proposals(&[f]);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.id, "EWP-001");
        assert_eq!(p.capability, "fs-watch");
        assert_eq!(p.state, ImplementationState::Analysed);
        assert!(p.required_interface.contains("trait FileWatcher"));
        assert!(p.estimated_effort_days > 0);
    }

    #[test]
    fn no_inotify_no_proposal() {
        let f = Finding::new(
            PlatformDependency::Filesystem,
            CompatibilityState::Adaptable,
            Severity::Minor,
            "unix-style path join in string literal",
            None,
        );
        assert!(generate_proposals(&[f]).is_empty());
    }

    #[test]
    fn fs_watch_is_declared_supported() {
        assert!(proposal_supported("fs-watch"));
        assert!(!proposal_supported("ipc:bus"));
    }
}
