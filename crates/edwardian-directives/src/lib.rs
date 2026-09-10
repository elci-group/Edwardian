use edwardian_core::{
    CompatibilityState, Directive, DirectivePriority, Finding, Severity,
};
use edwardian_resolver::{capability_key, AlternativeRegistry};

/// Generate remediation directives from classified findings. Blockers become
/// P0, Majors P1, Minors P2; Info findings get no directive. Remediation text
/// is seeded from the top-ranked alternative in the decision hierarchy.
pub fn generate_directives(findings: &[Finding], registry: &AlternativeRegistry) -> Vec<Directive> {
    let mut directives: Vec<Directive> = Vec::new();
    let mut src_finding_ids: Vec<String> = Vec::new();
    for finding in findings {
        let priority = match finding.severity {
            Severity::Blocker => DirectivePriority::P0,
            Severity::Major => DirectivePriority::P1,
            Severity::Minor => DirectivePriority::P2,
            Severity::Info => continue,
        };
        let id = format!("EWD-D{:03}", directives.len() + 1);

        let evidence_ids = finding.evidence.iter().map(|e| e.id.clone()).collect();
        let mut components: Vec<String> = finding
            .evidence
            .iter()
            .map(|e| {
                let p = &e.location.path;
                match p.rfind('/') {
                    Some(i) => p[..i].to_string(),
                    None => ".".to_string(),
                }
            })
            .collect();
        components.sort();
        components.dedup();

        let remediation = match capability_key(finding) {
            Some(cap) => {
                let alts = registry.alternatives_for(cap);
                match (finding.remediation_hint.as_ref(), alts.first()) {
                    (Some(hint), Some(alt)) => format!(
                        "{} Recommended path ({}): {} — {}.",
                        hint,
                        alt.strategy.label(),
                        alt.name,
                        alt.rationale
                    ),
                    (Some(hint), None) => hint.clone(),
                    (None, Some(alt)) => format!(
                        "Adopt {} ({}): {}.",
                        alt.name,
                        alt.strategy.label(),
                        alt.rationale
                    ),
                    (None, None) => "No automated remediation available; manual port required."
                        .to_string(),
                }
            }
            None => finding
                .remediation_hint
                .clone()
                .unwrap_or_else(|| "No remediation required (portable).".to_string()),
        };

        let src_finding_id = finding.id.clone();
        src_finding_ids.push(src_finding_id);
        directives.push(Directive {
            id,
            priority,
            objective: format!(
                "Remove {} ({} readiness impact)",
                finding.description,
                finding.severity.label()
            ),
            evidence_ids,
            affected_components: components,
            current_state: finding.state,
            target_state: CompatibilityState::WindowsCompatible,
            remediation,
            validation_plan: default_validation_plan(finding.severity),
            dependencies: Vec::new(),
        });
    }

    link_by_component_overlap(&mut directives, &src_finding_ids);
    directives
}

/// Derive directive dependencies from shared affected components: two
/// directives that touch the same component get an edge from the more urgent
/// one (lower priority value, ties broken by source finding id) to the other,
/// meaning the less urgent directive depends on the more urgent one. Edges
/// always follow the total urgency order, so the graph is acyclic by
/// construction.
fn link_by_component_overlap(directives: &mut [Directive], src_finding_ids: &[String]) {
    for i in 0..directives.len() {
        for j in (i + 1)..directives.len() {
            let shared = directives[i]
                .affected_components
                .iter()
                .any(|c| directives[j].affected_components.contains(c));
            if !shared {
                continue;
            }
            let i_urgency = (directives[i].priority, src_finding_ids[i].clone());
            let j_urgency = (directives[j].priority, src_finding_ids[j].clone());
            let (from, to) = if i_urgency <= j_urgency { (i, j) } else { (j, i) };
            let from_id = directives[from].id.clone();
            if !directives[to].dependencies.contains(&from_id) {
                directives[to].dependencies.push(from_id);
            }
        }
    }
}

/// Deterministic topological order over directive dependencies (Kahn's
/// algorithm, ties broken by directive id). Cycles should be impossible given
/// the construction above; any leftover nodes are appended by id.
pub fn topo_order(directives: &[Directive]) -> Vec<usize> {
    let pos = |id: &str| directives.iter().position(|d| d.id == id);
    let mut indeg: Vec<usize> = directives
        .iter()
        .map(|d| d.dependencies.iter().filter_map(|x| pos(x)).count())
        .collect();
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); directives.len()];
    for (i, d) in directives.iter().enumerate() {
        for dep in &d.dependencies {
            if let Some(j) = pos(dep) {
                edges[j].push(i);
            }
        }
    }
    let mut ready: Vec<usize> = (0..directives.len())
        .filter(|&i| indeg[i] == 0)
        .collect();
    let mut order = Vec::with_capacity(directives.len());
    while let Some(i) = ready.first().copied() {
        ready.remove(0);
        order.push(i);
        for &k in edges[i].iter() {
            indeg[k] -= 1;
            if indeg[k] == 0 {
                ready.push(k);
            }
        }
        ready.sort_by_key(|&k| directives[k].id.clone());
    }
    for i in 0..directives.len() {
        if !order.contains(&i) {
            order.push(i);
        }
    }
    order
}

fn default_validation_plan(severity: Severity) -> Vec<String> {
    let mut plan = vec![
        "Linux build passes (cargo build)".to_string(),
        "Windows build passes (cargo build --target x86_64-pc-windows-msvc)".to_string(),
        "Unit test suite passes on both platforms".to_string(),
    ];
    if severity >= Severity::Major {
        plan.push("Output equivalence test: Linux vs Windows behaviour identical on a golden input".to_string());
        plan.push("CI matrix (ubuntu-latest, windows-latest) passes".to_string());
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::{Location, PlatformDependency};
    use edwardian_evidence::EvidenceFactory;

    fn finding(sev: Severity, desc: &str) -> Finding {
        let dep = if desc.contains("systemd") {
            PlatformDependency::Service
        } else {
            PlatformDependency::Shell
        };
        let mut f = Finding::new(
            dep,
            CompatibilityState::RequiresImplementation,
            sev,
            desc,
            Some("replace with native API".to_string()),
        );
        let mut factory = EvidenceFactory::new();
        f.evidence.push(factory.file_scan(
            Location::new("src/main.rs", 3, 7),
            "evidence",
            0.9,
            "test",
        ));
        f
    }

    #[test]
    fn blocker_is_p0_and_has_complete_plan() {
        let reg = AlternativeRegistry::seeded();
        let ds = generate_directives(&[finding(Severity::Blocker, "systemd service integration")], &reg);
        assert_eq!(ds.len(), 1);
        let d = &ds[0];
        assert_eq!(d.priority, DirectivePriority::P0);
        assert!(d.validation_plan_is_complete());
        assert_eq!(d.target_state, CompatibilityState::WindowsCompatible);
        assert!(d.remediation.contains("service-manager"));
    }

    #[test]
    fn info_findings_produce_no_directive() {
        let reg = AlternativeRegistry::seeded();
        let ds = generate_directives(&[finding(Severity::Info, "git invocation")], &reg);
        assert!(ds.is_empty());
    }

    #[test]
    fn directives_sharing_components_get_dependency_edges() {
        let reg = AlternativeRegistry::seeded();
        // Both findings carry evidence in src/main.rs -> shared component.
        let findings = vec![
            finding(Severity::Blocker, "systemd service integration"),
            finding(Severity::Major, "unix domain socket usage"),
        ];
        let ds = generate_directives(&findings, &reg);
        assert_eq!(ds.len(), 2);
        // Edge runs from the more urgent (P0) directive to the less urgent one.
        assert_eq!(ds[0].dependencies, Vec::<String>::new());
        assert_eq!(ds[1].dependencies, vec!["EWD-D001".to_string()]);
        // The graph is acyclic and topo order respects every edge.
        let order = topo_order(&ds);
        assert_eq!(order.len(), 2);
        let pos0 = order.iter().position(|&i| i == 0).unwrap();
        let pos1 = order.iter().position(|&i| i == 1).unwrap();
        assert!(pos0 < pos1);
    }

    #[test]
    fn disjoint_components_have_no_edges_and_graph_stays_acyclic() {
        let reg = AlternativeRegistry::seeded();
        let mut a = finding(Severity::Blocker, "systemd service integration");
        a.evidence[0].location.path = "src/main.rs".to_string();
        let mut b = finding(Severity::Major, "unix domain socket usage");
        b.evidence[0].location.path = "src/main.rs".to_string();
        let mut c = finding(Severity::Major, "Makefile-driven build");
        c.evidence[0].location.path = "Makefile".to_string();
        let ds = generate_directives(&[a, b, c], &reg);
        assert_eq!(ds.len(), 3);
        // Makefile directive shares no component with the src/ pair.
        assert!(ds[2].dependencies.is_empty());
        // Cycle check: topo order covers all nodes with every edge respected.
        let order = topo_order(&ds);
        assert_eq!(order.len(), 3);
        let pos = |id: &str| order.iter().position(|&i| ds[i].id == id).unwrap();
        for d in &ds {
            for dep in &d.dependencies {
                assert!(pos(dep) < pos(&d.id));
            }
        }
    }

    #[test]
    fn same_priority_ties_break_by_finding_id() {
        let reg = AlternativeRegistry::seeded();
        let mut a = finding(Severity::Major, "unix domain socket usage");
        a.id = "FND-00002".to_string();
        a.evidence[0].id = "EWD-00002".to_string();
        let mut b = finding(Severity::Major, "cron scheduling dependency");
        b.id = "FND-00001".to_string();
        b.evidence[0].id = "EWD-00001".to_string();
        let ds = generate_directives(&[a, b], &reg);
        assert_eq!(ds.len(), 2);
        let socket = ds.iter().find(|d| d.objective.contains("socket")).unwrap();
        let cron = ds.iter().find(|d| d.objective.contains("cron")).unwrap();
        // Equal priority: the directive from finding FND-00001 (cron) is the
        // urgent one, so the socket directive depends on it.
        assert_eq!(cron.dependencies, Vec::<String>::new());
        assert_eq!(socket.dependencies, vec![cron.id.clone()]);
    }

    #[test]
    fn components_derived_from_evidence_paths() {
        let reg = AlternativeRegistry::seeded();
        let ds = generate_directives(&[finding(Severity::Major, "unix domain socket usage")], &reg);
        assert_eq!(ds[0].affected_components, vec!["src"]);
    }
}
