use crate::util::{col_of, is_comment, lines, loc};
use crate::{Detector, FileContext, FindingAccrual};
use edwardian_core::{CompatibilityState, Evidence, Finding, PlatformDependency, Severity};
use edwardian_evidence::EvidenceFactory;

pub struct ServiceDetector;

impl Detector for ServiceDetector {
    fn id(&self) -> &'static str {
        "services.unix"
    }

    fn run(&self, ctx: &FileContext, factory: &mut EvidenceFactory) -> Vec<Finding> {
        let mut accrual = FindingAccrual::new();
        for (line_no, line) in lines(ctx.content) {
            if is_comment(line, ctx.path) {
                continue;
            }
            for (token, key, dep, state, severity, description, hint) in RULES {
                if let Some(col) = col_of(line, token) {
                    let ev: Evidence = factory.file_scan(
                        loc(ctx.path, line_no, col),
                        format!("reference to `{}`", token),
                        0.9,
                        self.id(),
                    );
                    accrual.add(
                        key,
                        || {
                            Finding::new(
                                *dep,
                                *state,
                                *severity,
                                *description,
                                Some(hint.to_string()),
                            )
                        },
                        ev,
                    );
                }
            }
        }
        accrual.into_findings()
    }
}

#[allow(clippy::type_complexity)]
const RULES: &[(
    &str,
    &str,
    PlatformDependency,
    CompatibilityState,
    Severity,
    &str,
    &str,
)] = &[
    (
        "systemd",
        "systemd",
        PlatformDependency::Service,
        CompatibilityState::RequiresImplementation,
        Severity::Blocker,
        "systemd service integration",
        "register as a Windows Service (service-manager crate) or use the Task Scheduler",
    ),
    (
        "systemctl",
        "systemd",
        PlatformDependency::Service,
        CompatibilityState::RequiresImplementation,
        Severity::Blocker,
        "systemd service integration",
        "register as a Windows Service (service-manager crate) or use the Task Scheduler",
    ),
    (
        "launchd",
        "launchd",
        PlatformDependency::Service,
        CompatibilityState::Replaceable,
        Severity::Major,
        "launchd service integration (macOS-specific)",
        "replace with the Windows Service Control Manager or Task Scheduler",
    ),
    (
        "udev",
        "udev",
        PlatformDependency::Kernel,
        CompatibilityState::Replaceable,
        Severity::Major,
        "udev device management dependency",
        "use WMI / SetupAPI / cfgmgr32 for device events on Windows",
    ),
    (
        "crontab",
        "cron",
        PlatformDependency::Service,
        CompatibilityState::Replaceable,
        Severity::Major,
        "cron scheduling dependency",
        "use the Windows Task Scheduler (scheduled tasks via schtasks or windows crate)",
    ),
    (
        "/etc/cron",
        "cron",
        PlatformDependency::Service,
        CompatibilityState::Replaceable,
        Severity::Major,
        "cron scheduling dependency",
        "use the Windows Task Scheduler (scheduled tasks via schtasks or windows crate)",
    ),
    (
        "init.d",
        "initd",
        PlatformDependency::Service,
        CompatibilityState::Replaceable,
        Severity::Major,
        "SysV init script dependency",
        "replace with the Windows Service Control Manager",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use edwardian_core::Platform;

    fn scan(content: &str) -> Vec<Finding> {
        ServiceDetector.run(
            &FileContext::new("app.service", content, Platform::Windows),
            &mut EvidenceFactory::new(),
        )
    }

    #[test]
    fn systemd_is_blocker() {
        let findings = scan("[Unit]\nDescription=app managed by systemd\n[Service]\nExecStart=/usr/bin/myapp\n");
        let f = findings.iter().find(|f| f.description.contains("systemd")).unwrap();
        assert_eq!(f.severity, Severity::Blocker);
        assert_eq!(f.dependency, PlatformDependency::Service);
    }

    #[test]
    fn cron_and_udev_are_major() {
        let findings = scan("* * * * * root /usr/bin/backup\n0 3 * * * root /etc/cron.d/nightly\ncat /etc/udev/rules.d/99-x.rules\n");
        assert!(findings.iter().any(|f| f.description.contains("cron")));
        assert!(findings.iter().any(|f| f.description.contains("udev")));
        assert!(findings.iter().all(|f| f.severity != Severity::Blocker));
    }

    #[test]
    fn negative_plain_words() {
        assert!(scan("systematic launch delay\n").is_empty());
        assert!(scan("initialize the daemon\n").is_empty());
    }
}
