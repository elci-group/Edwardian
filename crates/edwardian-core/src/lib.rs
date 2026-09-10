use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Linux,
    Windows,
    MacOs,
    FreeBsd,
    OpenBsd,
    Android,
    Ios,
    Wasm,
}

impl Platform {
    pub fn label(self) -> &'static str {
        match self {
            Platform::Linux => "Linux",
            Platform::Windows => "Windows",
            Platform::MacOs => "macOS",
            Platform::FreeBsd => "FreeBSD",
            Platform::OpenBsd => "OpenBSD",
            Platform::Android => "Android",
            Platform::Ios => "iOS",
            Platform::Wasm => "WebAssembly",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformDependency {
    None,
    Configuration,
    Tooling,
    BuildSystem,
    Runtime,
    Filesystem,
    Process,
    Shell,
    Service,
    #[serde(rename = "ipc")]
    IPC,
    Kernel,
    NativeLibrary,
    ABI,
    Compiler,
    PackageManager,
    Container,
    CI,
    Deployment,
    Architecture,
    Unknown,
}

impl PlatformDependency {
    pub fn label(self) -> &'static str {
        match self {
            PlatformDependency::None => "none",
            PlatformDependency::Configuration => "configuration",
            PlatformDependency::Tooling => "tooling",
            PlatformDependency::BuildSystem => "build-system",
            PlatformDependency::Runtime => "runtime",
            PlatformDependency::Filesystem => "filesystem",
            PlatformDependency::Process => "process",
            PlatformDependency::Shell => "shell",
            PlatformDependency::Service => "service",
            PlatformDependency::IPC => "ipc",
            PlatformDependency::Kernel => "kernel",
            PlatformDependency::NativeLibrary => "native-library",
            PlatformDependency::ABI => "abi",
            PlatformDependency::Compiler => "compiler",
            PlatformDependency::PackageManager => "package-manager",
            PlatformDependency::Container => "container",
            PlatformDependency::CI => "ci",
            PlatformDependency::Deployment => "deployment",
            PlatformDependency::Architecture => "architecture",
            PlatformDependency::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityState {
    Portable,
    WindowsCompatible,
    Configurable,
    Adaptable,
    Replaceable,
    RequiresImplementation,
    ArchitecturallyIncompatible,
    Unknown,
}

impl CompatibilityState {
    pub fn label(self) -> &'static str {
        match self {
            CompatibilityState::Portable => "portable",
            CompatibilityState::WindowsCompatible => "windows-compatible",
            CompatibilityState::Configurable => "configurable",
            CompatibilityState::Adaptable => "adaptable",
            CompatibilityState::Replaceable => "replaceable",
            CompatibilityState::RequiresImplementation => "requires-implementation",
            CompatibilityState::ArchitecturallyIncompatible => "architecturally-incompatible",
            CompatibilityState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Minor,
    Major,
    Blocker,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Minor => "minor",
            Severity::Major => "major",
            Severity::Blocker => "blocker",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationState {
    Analysed,
    Recommended,
    Implemented,
    Compiles,
    Tested,
    Validated,
}

impl ImplementationState {
    pub fn label(self) -> &'static str {
        match self {
            ImplementationState::Analysed => "analysed",
            ImplementationState::Recommended => "recommended",
            ImplementationState::Implemented => "implemented",
            ImplementationState::Compiles => "compiles",
            ImplementationState::Tested => "tested",
            ImplementationState::Validated => "validated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSource {
    FileScan,
    Manifest,
    RepoLayout,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub path: String,
    pub line: usize,
    pub column: usize,
}

impl Location {
    pub fn new(path: impl Into<String>, line: usize, column: usize) -> Self {
        Location {
            path: path.into(),
            line,
            column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: EvidenceSource,
    pub location: Location,
    pub observation: String,
    pub confidence: f32,
    pub detector: String,
}

impl Evidence {
    pub fn file_scan(
        id: impl Into<String>,
        location: Location,
        observation: impl Into<String>,
        confidence: f32,
        detector: impl Into<String>,
    ) -> Self {
        Evidence {
            id: id.into(),
            source: EvidenceSource::FileScan,
            location,
            observation: observation.into(),
            confidence: confidence.clamp(0.0, 1.0),
            detector: detector.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub evidence: Vec<Evidence>,
    pub dependency: PlatformDependency,
    pub state: CompatibilityState,
    pub severity: Severity,
    pub description: String,
    pub remediation_hint: Option<String>,
}

impl Finding {
    pub fn new(
        dependency: PlatformDependency,
        state: CompatibilityState,
        severity: Severity,
        description: impl Into<String>,
        remediation_hint: Option<String>,
    ) -> Self {
        Finding {
            id: String::new(),
            evidence: Vec::new(),
            dependency,
            state,
            severity,
            description: description.into(),
            remediation_hint,
        }
    }

    pub fn has_material_evidence(&self) -> bool {
        !self.evidence.is_empty()
            && self
                .evidence
                .iter()
                .all(|e| !e.location.path.is_empty() && e.confidence > 0.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionStrategy {
    ExistingPortable,
    ExistingWindowsCompatible,
    ConfigurationChange,
    FossSubstitution,
    ThinAdapter,
    NativeBackend,
    InHouseReplacement,
    ArchitecturalRedesign,
}

impl DecisionStrategy {
    pub fn label(self) -> &'static str {
        match self {
            DecisionStrategy::ExistingPortable => "existing-portable",
            DecisionStrategy::ExistingWindowsCompatible => "existing-windows-compatible",
            DecisionStrategy::ConfigurationChange => "configuration-change",
            DecisionStrategy::FossSubstitution => "foss-substitution",
            DecisionStrategy::ThinAdapter => "thin-adaptor",
            DecisionStrategy::NativeBackend => "native-backend",
            DecisionStrategy::InHouseReplacement => "in-house-replacement",
            DecisionStrategy::ArchitecturalRedesign => "architectural-redesign",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            DecisionStrategy::ExistingPortable => 0,
            DecisionStrategy::ExistingWindowsCompatible => 1,
            DecisionStrategy::ConfigurationChange => 2,
            DecisionStrategy::FossSubstitution => 3,
            DecisionStrategy::ThinAdapter => 4,
            DecisionStrategy::NativeBackend => 5,
            DecisionStrategy::InHouseReplacement => 6,
            DecisionStrategy::ArchitecturalRedesign => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Maturity {
    Stable,
    Beta,
    Experimental,
    Unmaintained,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alternative {
    pub name: String,
    pub capability: String,
    pub platforms: Vec<Platform>,
    pub license: String,
    pub maturity: Maturity,
    /// 1 (trivial) ..= 5 (major project)
    pub integration_cost: u8,
    /// 1 (low) ..= 5 (high)
    pub operational_risk: u8,
    pub strategy: DecisionStrategy,
    pub rationale: String,
}

impl Alternative {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        capability: impl Into<String>,
        platforms: Vec<Platform>,
        license: impl Into<String>,
        maturity: Maturity,
        integration_cost: u8,
        operational_risk: u8,
        strategy: DecisionStrategy,
        rationale: impl Into<String>,
    ) -> Self {
        Alternative {
            name: name.into(),
            capability: capability.into(),
            platforms,
            license: license.into(),
            maturity,
            integration_cost: integration_cost.clamp(1, 5),
            operational_risk: operational_risk.clamp(1, 5),
            strategy,
            rationale: rationale.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DirectivePriority {
    P0,
    P1,
    P2,
    P3,
}

impl DirectivePriority {
    pub fn label(self) -> &'static str {
        match self {
            DirectivePriority::P0 => "P0",
            DirectivePriority::P1 => "P1",
            DirectivePriority::P2 => "P2",
            DirectivePriority::P3 => "P3",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Directive {
    pub id: String,
    pub priority: DirectivePriority,
    pub objective: String,
    pub evidence_ids: Vec<String>,
    pub affected_components: Vec<String>,
    pub current_state: CompatibilityState,
    pub target_state: CompatibilityState,
    pub remediation: String,
    pub validation_plan: Vec<String>,
    pub dependencies: Vec<String>,
}

impl Directive {
    pub fn validation_plan_is_complete(&self) -> bool {
        !self.objective.trim().is_empty()
            && !self.remediation.trim().is_empty()
            && !self.validation_plan.is_empty()
            && self
                .validation_plan
                .iter()
                .all(|step| !step.trim().is_empty())
            && !self.evidence_ids.is_empty()
            && self
                .dependencies
                .iter()
                .all(|d| d.trim().starts_with("EWD-D"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub capability: String,
    pub current_impl: String,
    pub required_impl: String,
    pub recommended_architecture: String,
    pub required_interface: String,
    pub compatibility_invariant: String,
    pub estimated_effort_days: u32,
    pub risk: String,
    pub state: ImplementationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessStatus {
    Ready,
    Conditional,
    Blocked,
}

impl ReadinessStatus {
    pub fn label(self) -> &'static str {
        match self {
            ReadinessStatus::Ready => "READY",
            ReadinessStatus::Conditional => "CONDITIONAL",
            ReadinessStatus::Blocked => "BLOCKED",
        }
    }
}
