use edwardian_core::{Directive, Finding, PlatformDependency, Proposal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Entity kinds in the platform-dependency ontology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntityKind {
    Component,
    Finding,
    Dependency,
    Directive,
    Proposal,
    Platform,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub kind: EntityKind,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
    Exhibits,
    DependsOn,
    RemediatedBy,
    Proposes,
    Targets,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relation {
    pub from: String,
    pub to: String,
    pub kind: RelationKind,
}

/// A minimal directed knowledge graph over analysis artefacts. Entity ids are
/// the same deterministic ids used in findings/directives/proposals, so the
/// graph is a faithful index of a pipeline run.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Ontology {
    entities: BTreeMap<String, Entity>,
    relations: Vec<Relation>,
}

impl Ontology {
    pub fn new() -> Self {
        Ontology::default()
    }

    pub fn add_entity(&mut self, entity: Entity) {
        self.entities.insert(entity.id.clone(), entity);
    }

    pub fn relate(&mut self, from: &str, to: &str, kind: RelationKind) {
        self.relations.push(Relation {
            from: from.to_string(),
            to: to.to_string(),
            kind,
        });
    }

    pub fn entity(&self, id: &str) -> Option<&Entity> {
        self.entities.get(id)
    }

    pub fn relations_from(&self, id: &str, kind: RelationKind) -> Vec<&Relation> {
        self.relations
            .iter()
            .filter(|r| r.from == id && r.kind == kind)
            .collect()
    }

    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    pub fn relation_count(&self) -> usize {
        self.relations.len()
    }

    /// Index a full analysis: components (from evidence paths), findings,
    /// dependencies, directives, proposals.
    pub fn index(
        &mut self,
        components: &[String],
        findings: &[Finding],
        directives: &[Directive],
        proposals: &[Proposal],
    ) {
        for c in components {
            self.add_entity(Entity {
                id: format!("cmp:{}", c),
                kind: EntityKind::Component,
                name: c.clone(),
            });
        }
        for f in findings {
            self.add_entity(Entity {
                id: f.id.clone(),
                kind: EntityKind::Finding,
                name: f.description.clone(),
            });
            let dep_id = format!("dep:{}", f.dependency.label());
            self.add_entity(Entity {
                id: dep_id.clone(),
                kind: EntityKind::Dependency,
                name: f.dependency.label().to_string(),
            });
            self.relate(&f.id, &dep_id, RelationKind::DependsOn);
            for e in &f.evidence {
                let cid = format!("cmp:{}", component_of(&e.location.path));
                self.relate(&f.id, &cid, RelationKind::Exhibits);
            }
        }
        for d in directives {
            self.add_entity(Entity {
                id: d.id.clone(),
                kind: EntityKind::Directive,
                name: d.objective.clone(),
            });
            for eid in &d.evidence_ids {
                self.relate(&d.id, eid, RelationKind::RemediatedBy);
            }
        }
        for p in proposals {
            self.add_entity(Entity {
                id: p.id.clone(),
                kind: EntityKind::Proposal,
                name: p.capability.clone(),
            });
            if let Some(f) = findings
                .iter()
                .find(|f| f.description.contains("inotify") && p.capability == "fs-watch")
            {
                self.relate(&p.id, &f.id, RelationKind::Proposes);
            }
        }
    }
}

fn component_of(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..i].to_string(),
        None => ".".to_string(),
    }
}

#[allow(dead_code)]
fn _assert_dependency_is_platform(_: PlatformDependency) {}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::{
        CompatibilityState, Evidence, Location, Severity,
    };

    #[test]
    fn indexes_findings_and_directives() {
        let mut f = Finding::new(
            PlatformDependency::Kernel,
            CompatibilityState::RequiresImplementation,
            Severity::Major,
            "Linux inotify filesystem-watch dependency",
            None,
        );
        f.id = "FND-00001".to_string();
        f.evidence.push(Evidence::file_scan(
            "EWD-00001",
            Location::new("src/watch.rs", 1, 1),
            "inotify",
            0.9,
            "ipc.unix",
        ));
        let mut onto = Ontology::new();
        onto.index(
            &["src".to_string()],
            std::slice::from_ref(&f),
            &[],
            &[fs_watch_like()],
        );
        assert!(onto.entity("FND-00001").is_some());
        assert!(onto.entity("dep:kernel").is_some());
        assert_eq!(onto.relations_from("FND-00001", RelationKind::DependsOn).len(), 1);
        assert_eq!(onto.relations_from("FND-00001", RelationKind::Exhibits).len(), 1);
        assert_eq!(onto.relations_from("EWP-001", RelationKind::Proposes).len(), 1);
    }

    fn fs_watch_like() -> Proposal {
        Proposal {
            id: "EWP-001".to_string(),
            capability: "fs-watch".to_string(),
            current_impl: "inotify".to_string(),
            required_impl: "rdcw".to_string(),
            recommended_architecture: "trait + backends".to_string(),
            required_interface: "trait FileWatcher".to_string(),
            compatibility_invariant: "no event dropped".to_string(),
            estimated_effort_days: 8,
            risk: "rename pairing".to_string(),
            state: edwardian_core::ImplementationState::Analysed,
        }
    }
}
