use edwardian_core::{Evidence, Location};

/// Deterministic id allocator for evidence (`EWD-NNNNN`) and findings
/// (`FND-NNNNN`). Ids count from 1 within a single pipeline run.
#[derive(Debug, Default)]
pub struct IdAllocator {
    next_evidence: u32,
    next_finding: u32,
}

impl IdAllocator {
    pub fn new() -> Self {
        IdAllocator::default()
    }

    pub fn next_evidence_id(&mut self) -> String {
        self.next_evidence += 1;
        format!("EWD-{:05}", self.next_evidence)
    }

    pub fn next_finding_id(&mut self) -> String {
        self.next_finding += 1;
        format!("FND-{:05}", self.next_finding)
    }

    pub fn evidence_seen(&self) -> u32 {
        self.next_evidence
    }
}

/// Factory that stamps `Evidence` values with deterministic ids.
#[derive(Debug, Default)]
pub struct EvidenceFactory {
    ids: IdAllocator,
}

impl EvidenceFactory {
    pub fn new() -> Self {
        EvidenceFactory::default()
    }

    pub fn ids(&mut self) -> &mut IdAllocator {
        &mut self.ids
    }

    pub fn file_scan(
        &mut self,
        location: Location,
        observation: impl Into<String>,
        confidence: f32,
        detector: impl Into<String>,
    ) -> Evidence {
        let id = self.ids.next_evidence_id();
        Evidence::file_scan(id, location, observation, confidence, detector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_ids_are_sequential_from_one() {
        let mut ids = IdAllocator::new();
        assert_eq!(ids.next_evidence_id(), "EWD-00001");
        assert_eq!(ids.next_evidence_id(), "EWD-00002");
        assert_eq!(ids.next_finding_id(), "FND-00001");
        assert_eq!(ids.next_evidence_id(), "EWD-00003");
    }

    #[test]
    fn factory_clamps_confidence() {
        let mut f = EvidenceFactory::new();
        let e = f.file_scan(Location::new("a.rs", 1, 1), "obs", 1.7, "det");
        assert_eq!(e.confidence, 1.0);
        assert_eq!(e.id, "EWD-00001");
    }
}
