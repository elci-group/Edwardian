//! Incremental analysis daemon. Watches a repository with a std-only
//! snapshot diff (path, mtime/size proxy via content hash) over the same
//! bounded file set the engine walks, re-detects only new or changed files,
//! and keeps evidence/finding ids stable for unchanged content.
//!
//! Termination: no signal handlers are installed (std-only); stop the daemon
//! with SIGKILL/SIGTERM/default Ctrl-C semantics. `--once` exists for
//! scripted single-cycle runs.

use edwardian_core::{
    Alternative, Directive, Finding, Proposal,
};
use edwardian_detectors::{all_detectors, Detector, FileContext};
use edwardian_engine::{FileRecord, PipelineConfig, inventory};
use edwardian_evidence::{EvidenceFactory, IdAllocator};
use edwardian_report::{ReadinessReport, score_readiness};
use edwardian_resolver::{capability_key, AlternativeRegistry};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Pseudo cache key for the inventory-level case-sensitivity scan.
const CASE_SCAN_KEY: &str = "<edwardian:case-scan>";

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    FileAdded { path: String, size: u64 },
    FileChanged { path: String, size: u64 },
    FileRemoved { path: String },
    FindingAdded {
        finding_id: String,
        description: String,
        severity: String,
        path: String,
    },
    FindingRemoved {
        finding_id: String,
        description: String,
        severity: String,
        path: String,
    },
    ReadinessChanged {
        overall_before: u8,
        overall_after: u8,
        blocker_count_before: usize,
        blocker_count_after: usize,
    },
    StatusChanged { from: String, to: String },
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::FileAdded { .. } => "file_added",
            EventKind::FileChanged { .. } => "file_changed",
            EventKind::FileRemoved { .. } => "file_removed",
            EventKind::FindingAdded { .. } => "finding_added",
            EventKind::FindingRemoved { .. } => "finding_removed",
            EventKind::ReadinessChanged { .. } => "readiness_changed",
            EventKind::StatusChanged { .. } => "status_changed",
        }
    }

    /// One-line human summary.
    pub fn summary(&self) -> String {
        match self {
            EventKind::FileAdded { path, size } => {
                format!("file_added   {} ({} bytes)", path, size)
            }
            EventKind::FileChanged { path, size } => {
                format!("file_changed {} ({} bytes)", path, size)
            }
            EventKind::FileRemoved { path } => format!("file_removed {}", path),
            EventKind::FindingAdded {
                finding_id,
                description,
                severity,
                path,
            }
            | EventKind::FindingRemoved {
                finding_id,
                description,
                severity,
                path,
            } => format!(
                "{:<14} {} [{}] {} @ {}",
                self.name(),
                finding_id,
                severity,
                description,
                path
            ),
            EventKind::ReadinessChanged {
                overall_before,
                overall_after,
                blocker_count_before,
                blocker_count_after,
            } => format!(
                "readiness_changed {}% -> {}% (blockers {} -> {})",
                overall_before, overall_after, blocker_count_before, blocker_count_after
            ),
            EventKind::StatusChanged { from, to } => {
                format!("status_changed {} -> {}", from, to)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DaemonEvent {
    pub cycle: u64,
    pub timestamp_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl DaemonEvent {
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

#[derive(Debug, Clone)]
pub struct CycleOutput {
    pub cycle: u64,
    pub events: Vec<DaemonEvent>,
    pub findings: Vec<Finding>,
    pub readiness: ReadinessReport,
    pub directives: Vec<Directive>,
    pub proposals: Vec<Proposal>,
    pub alternatives: BTreeMap<String, Vec<Alternative>>,
}

#[derive(Debug, Clone, Default)]
struct FileCacheEntry {
    hash: u64,
    findings: Vec<Finding>,
}

fn content_hash(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// Stable identity for a finding within the diff: detector, description and
/// the full evidence location set (so a mutated file that gains a second
/// occurrence of a pattern is a remove+add pair, not a silent merge).
fn finding_key(f: &Finding) -> String {
    let det = f
        .evidence
        .first()
        .map(|e| e.detector.clone())
        .unwrap_or_else(|| "?".to_string());
    let locs = f
        .evidence
        .iter()
        .map(|e| format!("{}:{}:{}", e.location.path, e.location.line, e.location.column))
        .collect::<Vec<_>>()
        .join(",");
    format!("{}|{}|{}", det, f.description, locs)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Daemon {
    root: PathBuf,
    config: PipelineConfig,
    cache: BTreeMap<String, FileCacheEntry>,
    factory: EvidenceFactory,
    ids: IdAllocator,
    cycle: u64,
    last_readiness: Option<ReadinessReport>,
    detectors: Vec<Box<dyn Detector>>,
    registry: AlternativeRegistry,
}

impl Daemon {
    pub fn new(root: PathBuf, config: PipelineConfig) -> Self {
        Daemon {
            root,
            config,
            cache: BTreeMap::new(),
            factory: EvidenceFactory::new(),
            ids: IdAllocator::new(),
            cycle: 0,
            last_readiness: None,
            detectors: all_detectors(),
            registry: AlternativeRegistry::seeded(),
        }
    }

    pub fn cycle_count(&self) -> u64 {
        self.cycle
    }

    /// Run one poll cycle: snapshot diff, incremental re-detection, readiness
    /// recompute, event emission.
    pub fn cycle(&mut self) -> io::Result<CycleOutput> {
        self.cycle += 1;
        let cycle_no = self.cycle;
        let ts = now_ms();
        let mut events: Vec<DaemonEvent> = Vec::new();
        let ev = |kind: EventKind| DaemonEvent {
            cycle: cycle_no,
            timestamp_ms: ts,
            kind,
        };

        let (files, _skipped_binary, _skipped_limits) =
            inventory(&self.root, &self.config)?;

        let mut prev_findings: BTreeMap<String, Finding> = BTreeMap::new();
        for entry in self.cache.values() {
            for f in &entry.findings {
                prev_findings.insert(finding_key(f), f.clone());
            }
        }

        let mut seen: BTreeSet<String> = BTreeSet::new();
        for rec in &files {
            seen.insert(rec.path.clone());
            let full = self.root.join(&rec.path);
            let Ok(content) = fs::read_to_string(&full) else {
                continue;
            };
            let hash = content_hash(content.as_bytes());
            match self.cache.get(&rec.path) {
                Some(entry) if entry.hash == hash => {}
                Some(_) => {
                    events.push(ev(EventKind::FileChanged {
                        path: rec.path.clone(),
                        size: rec.size,
                    }));
                    let findings = self.detect_file(&rec.path, &content);
                    self.cache.insert(rec.path.clone(), FileCacheEntry { hash, findings });
                }
                None => {
                    events.push(ev(EventKind::FileAdded {
                        path: rec.path.clone(),
                        size: rec.size,
                    }));
                    let findings = self.detect_file(&rec.path, &content);
                    self.cache.insert(rec.path.clone(), FileCacheEntry { hash, findings });
                }
            }
        }

        // Inventory-level case-sensitivity scan, re-run only when the path set
        // changes (hash of the sorted path list).
        let path_list_hash = content_hash(files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>().join("\n").as_bytes());
        if self
            .cache
            .get(CASE_SCAN_KEY)
            .map(|e| e.hash != path_list_hash)
            .unwrap_or(true)
        {
            let paths: Vec<String> = files.iter().map(|f| f.path.clone()).collect();
            let mut findings =
                edwardian_detectors::fs::case_collision_findings(&paths, self.config.target, &mut self.factory);
            for f in &mut findings {
                f.id = self.ids.next_finding_id();
            }
            self.cache.insert(
                CASE_SCAN_KEY.to_string(),
                FileCacheEntry { hash: path_list_hash, findings },
            );
        }

        // Removed files.
        let stale: Vec<String> = self
            .cache
            .keys()
            .filter(|k| *k != CASE_SCAN_KEY && !seen.contains(*k))
            .cloned()
            .collect();
        for path in stale {
            self.cache.remove(&path);
            events.push(ev(EventKind::FileRemoved { path }));
        }

        // Finding diff.
        let mut new_findings: BTreeMap<String, Finding> = BTreeMap::new();
        for entry in self.cache.values() {
            for f in &entry.findings {
                new_findings.insert(finding_key(f), f.clone());
            }
        }
        for (key, f) in &new_findings {
            if !prev_findings.contains_key(key) {
                events.push(ev(EventKind::FindingAdded {
                    finding_id: f.id.clone(),
                    description: f.description.clone(),
                    severity: f.severity.label().to_string(),
                    path: f
                        .evidence
                        .first()
                        .map(|e| e.location.path.clone())
                        .unwrap_or_default(),
                }));
            }
        }
        for (key, f) in &prev_findings {
            if !new_findings.contains_key(key) {
                events.push(ev(EventKind::FindingRemoved {
                    finding_id: f.id.clone(),
                    description: f.description.clone(),
                    severity: f.severity.label().to_string(),
                    path: f
                        .evidence
                        .first()
                        .map(|e| e.location.path.clone())
                        .unwrap_or_default(),
                }));
            }
        }

        // Recompute aggregate state.
        let mut findings: Vec<Finding> = new_findings.into_values().collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        let readiness = score_readiness(self.config.target, &findings);

        match &self.last_readiness {
            None => {
                events.push(ev(EventKind::StatusChanged {
                    from: "UNKNOWN".to_string(),
                    to: readiness.status.label().to_string(),
                }));
            }
            Some(prev) => {
                if prev.overall != readiness.overall || prev.blocker_count != readiness.blocker_count
                {
                    events.push(ev(EventKind::ReadinessChanged {
                        overall_before: prev.overall,
                        overall_after: readiness.overall,
                        blocker_count_before: prev.blocker_count,
                        blocker_count_after: readiness.blocker_count,
                    }));
                }
                if prev.status != readiness.status {
                    events.push(ev(EventKind::StatusChanged {
                        from: prev.status.label().to_string(),
                        to: readiness.status.label().to_string(),
                    }));
                }
            }
        }
        self.last_readiness = Some(readiness.clone());

        let mut alternatives: BTreeMap<String, Vec<Alternative>> = BTreeMap::new();
        for f in &findings {
            if let Some(cap) = capability_key(f) {
                let alts = self.registry.alternatives_for(cap);
                if !alts.is_empty() {
                    alternatives.insert(f.id.clone(), alts);
                }
            }
        }
        let directives = edwardian_directives::generate_directives(&findings, &self.registry);
        let proposals = edwardian_proposals::generate_proposals(&findings);

        Ok(CycleOutput {
            cycle: cycle_no,
            events,
            findings,
            readiness,
            directives,
            proposals,
            alternatives,
        })
    }

    /// Detect all detectors over one file; assigns fresh finding ids
    /// (evidence ids come from the shared factory).
    fn detect_file(&mut self, path: &str, content: &str) -> Vec<Finding> {
        let ctx = FileContext::new(path, content, self.config.target);
        let mut out = Vec::new();
        for det in &self.detectors {
            for mut finding in det.run(&ctx, &mut self.factory) {
                finding.id = self.ids.next_finding_id();
                out.push(finding);
            }
        }
        out.retain(|f| !f.evidence.is_empty());
        out
    }
}

#[allow(dead_code)]
fn _keep(rec: FileRecord) {
    let _ = rec;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_is_line_delimited_and_tagged() {
        let e = DaemonEvent {
            cycle: 7,
            timestamp_ms: 42,
            kind: EventKind::StatusChanged {
                from: "READY".to_string(),
                to: "BLOCKED".to_string(),
            },
        };
        let v: serde_json::Value = serde_json::from_str(&e.to_json_line()).unwrap();
        assert_eq!(v["kind"], "status_changed");
        assert_eq!(v["cycle"], 7);
        assert_eq!(v["timestamp_ms"], 42);
        assert_eq!(v["from"], "READY");
        assert!(!e.to_json_line().contains('\n'));
    }

    #[test]
    fn event_names_and_summaries() {
        let k = EventKind::FileChanged { path: "a.rs".into(), size: 3 };
        assert_eq!(k.name(), "file_changed");
        assert!(k.summary().contains("a.rs"));
        let k = EventKind::ReadinessChanged {
            overall_before: 100,
            overall_after: 40,
            blocker_count_before: 0,
            blocker_count_after: 2,
        };
        assert!(k.summary().contains("100% -> 40%"));
    }
}
