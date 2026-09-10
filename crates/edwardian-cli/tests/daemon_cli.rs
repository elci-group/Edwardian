use std::process::Command;

#[test]
fn daemon_once_emits_json_event_lines() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::linux_only_repo(dir.path()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_edwardian"))
        .args([
            "daemon",
            "--once",
            "--format",
            "json",
            "--path",
            dir.path().to_str().unwrap(),
            "--out",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "no event output");
    let mut saw_status = false;
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON line {line:?}: {e}"));
        assert!(v["kind"].is_string());
        assert_eq!(v["cycle"], 1);
        assert!(v["timestamp_ms"].as_u64().is_some());
        if v["kind"] == "status_changed" {
            saw_status = true;
            assert_eq!(v["to"], "BLOCKED");
        }
    }
    assert!(saw_status, "expected a status_changed event in: {stdout}");
}

#[test]
fn daemon_once_human_summary() {
    let dir = tempfile::tempdir().unwrap();
    edwardian_test::portable_repo(dir.path()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_edwardian"))
        .args(["daemon", "--once", "--path", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("[cycle 1] status_changed UNKNOWN -> READY"), "got: {stdout}");
}
