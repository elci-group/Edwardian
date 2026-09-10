use edwardian_core::Finding;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Capability-based integration facade. Consumers (CLI, future daemon mode)
/// depend only on these capabilities, never on engine internals — the engine
/// registers providers, callers invoke capabilities by name.
pub trait CapabilityProvider: Send + Sync {
    fn provider_id(&self) -> &'static str;
    fn capabilities(&self) -> Vec<&'static str>;
    fn invoke(&self, capability: &str, input: &Value) -> Result<Value, String>;
}

/// Registry mapping capability names to providers. First registration wins
/// for a capability; later duplicates are rejected to stay deterministic.
#[derive(Default)]
pub struct CapabilityRegistry {
    providers: BTreeMap<&'static str, Box<dyn CapabilityProvider>>,
    routes: BTreeMap<String, &'static str>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        CapabilityRegistry::default()
    }

    pub fn register(&mut self, provider: Box<dyn CapabilityProvider>) -> Result<(), String> {
        let pid = provider.provider_id();
        for cap in provider.capabilities() {
            if self.routes.contains_key(cap) {
                return Err(format!(
                    "capability `{}` already provided by `{}`",
                    cap,
                    self.routes[cap]
                ));
            }
        }
        for cap in provider.capabilities() {
            self.routes.insert(cap.to_string(), pid);
        }
        self.providers.insert(pid, provider);
        Ok(())
    }

    pub fn invoke(&self, capability: &str, input: &Value) -> Result<Value, String> {
        let pid = self
            .routes
            .get(capability)
            .ok_or_else(|| format!("no provider for capability `{}`", capability))?;
        self.providers[pid].invoke(capability, input)
    }

    pub fn capabilities(&self) -> Vec<String> {
        self.routes.keys().cloned().collect()
    }
}

/// Read-only lookup capability over analysed findings.
pub struct FindingsProvider {
    findings: Vec<Finding>,
}

impl FindingsProvider {
    pub fn new(findings: Vec<Finding>) -> Self {
        FindingsProvider { findings }
    }
}

impl CapabilityProvider for FindingsProvider {
    fn provider_id(&self) -> &'static str {
        "edwardian.findings"
    }

    fn capabilities(&self) -> Vec<&'static str> {
        vec!["findings.list", "findings.get"]
    }

    fn invoke(&self, capability: &str, input: &Value) -> Result<Value, String> {
        match capability {
            "findings.list" => Ok(serde_json::to_value(&self.findings)
                .map_err(|e| e.to_string())?),
            "findings.get" => {
                let id = input
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or("input requires string field `id`")?;
                match self.findings.iter().find(|f| f.id == id) {
                    Some(f) => serde_json::to_value(f).map_err(|e| e.to_string()),
                    None => Err(format!("finding `{}` not found", id)),
                }
            }
            other => Err(format!("unsupported capability `{}`", other)),
        }
    }
}

/// Health/status capability every deployment exposes.
pub struct StatusProvider {
    run_metadata: Value,
}

impl StatusProvider {
    pub fn new(run_metadata: Value) -> Self {
        StatusProvider { run_metadata }
    }
}

impl CapabilityProvider for StatusProvider {
    fn provider_id(&self) -> &'static str {
        "edwardian.status"
    }

    fn capabilities(&self) -> Vec<&'static str> {
        vec!["status.health"]
    }

    fn invoke(&self, capability: &str, _input: &Value) -> Result<Value, String> {
        match capability {
            "status.health" => Ok(json!({
                "status": "ok",
                "providers": ["edwardian.findings", "edwardian.status"],
                "run": self.run_metadata,
            })),
            other => Err(format!("unsupported capability `{}`", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_routes_and_rejects_duplicates() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Box::new(StatusProvider::new(json!({"target": "windows"}))))
            .unwrap();
        let health = reg.invoke("status.health", &json!({})).unwrap();
        assert_eq!(health["status"], "ok");

        let err = reg
            .register(Box::new(StatusProvider::new(json!({}))))
            .unwrap_err();
        assert!(err.contains("already provided"));
        assert!(reg.invoke("nope.missing", &json!({})).is_err());
    }

    #[test]
    fn findings_provider_get_by_id() {
        let mut f = Finding::new(
            edwardian_core::PlatformDependency::Shell,
            edwardian_core::CompatibilityState::RequiresImplementation,
            edwardian_core::Severity::Blocker,
            "test finding",
            None,
        );
        f.id = "FND-00001".to_string();
        let reg_provider = FindingsProvider::new(vec![f]);
        let got = reg_provider
            .invoke("findings.get", &json!({"id": "FND-00001"}))
            .unwrap();
        assert_eq!(got["id"], "FND-00001");
        assert!(reg_provider.invoke("findings.get", &json!({"id": "X"})).is_err());
    }
}
