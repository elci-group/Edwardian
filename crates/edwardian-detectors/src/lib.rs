use edwardian_core::{Evidence, Finding};
use edwardian_evidence::EvidenceFactory;

pub mod build;
pub mod env;
pub mod fs;
pub mod fs_semantics;
pub mod ipc;
pub mod services;
pub mod shell;
pub mod util;
pub mod win_paths;

use edwardian_core::Platform;

/// A single text file presented to detectors. `path` is repo-relative with
/// forward slashes. `target` is the platform readiness is assessed for;
/// target-aware detectors classify evidence by its consequence there.
pub struct FileContext<'a> {
    pub path: &'a str,
    pub content: &'a str,
    pub target: Platform,
}

impl<'a> FileContext<'a> {
    pub fn new(path: &'a str, content: &'a str, target: Platform) -> Self {
        FileContext { path, content, target }
    }

    pub fn basename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }

    pub fn extension(&self) -> Option<&str> {
        self.basename().rsplit_once('.').map(|(_, e)| e)
    }

    pub fn is_shell_flavored(&self) -> bool {
        matches!(
            self.extension(),
            Some("sh" | "bash" | "zsh" | "ksh")
        ) || self.basename().starts_with("Makefile")
            || self.path.ends_with(".mk")
    }
}

pub trait Detector {
    fn id(&self) -> &'static str;
    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding>;
}

pub fn all_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(fs::FilesystemDetector),
        Box::new(fs_semantics::FilesystemSemanticsDetector),
        Box::new(win_paths::WindowsPathDetector),
        Box::new(shell::ShellProcessDetector),
        Box::new(services::ServiceDetector),
        Box::new(ipc::IpcDetector),
        Box::new(build::BuildSystemDetector),
        Box::new(env::EnvironmentDetector),
    ]
}

/// Groups evidence into findings keyed by a category within one detector run.
pub(crate) struct FindingAccrual {
    entries: Vec<(&'static str, Finding)>,
    evidence_cap: usize,
}

impl FindingAccrual {
    pub(crate) fn new() -> Self {
        FindingAccrual {
            entries: Vec::new(),
            evidence_cap: 8,
        }
    }

    pub(crate) fn add(
        &mut self,
        key: &'static str,
        make: impl FnOnce() -> Finding,
        evidence: Evidence,
    ) {
        let entry = match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, f)) => f,
            None => {
                self.entries.push((key, make()));
                &mut self.entries.last_mut().unwrap().1
            }
        };
        if entry.evidence.len() < self.evidence_cap {
            entry.evidence.push(evidence);
        }
    }

    pub(crate) fn into_findings(self) -> Vec<Finding> {
        self.entries
            .into_iter()
            .map(|(_, f)| f)
            .filter(|f| !f.evidence.is_empty())
            .collect()
    }
}
