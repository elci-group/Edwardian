//! Fixture repositories for integration tests. Each builder writes a small
//! synthetic repo into a directory; tests then run the full engine over it.
use std::fs;
use std::io;
use std::path::Path;

pub fn write(root: &Path, rel: &str, content: &str) -> io::Result<()> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

/// Repo full of unix-isms: bash, systemd, inotify, POSIX paths, unix sockets,
/// a Makefile, cron. Expect BLOCKED with blocker findings and proposals.
pub fn linux_only_repo(root: &Path) -> io::Result<()> {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"linuxdaemon\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    write(
        root,
        "src/main.rs",
        r#"use std::os::unix::net::UnixListener;
use std::process::Command;

fn main() {
    let _listener = UnixListener::bind("/tmp/app.sock").unwrap();
    let conf = "/etc/linuxdaemon/config.toml";
    println!("loading {}", conf);
    let _home = std::env::var("HOME").unwrap();
    Command::new("/bin/bash").arg("helper.sh").status().unwrap();
    let watcher = inotify::Inotify::init().unwrap();
    let _ = watcher;
}
"#,
    )?;
    write(root, "helper.sh", "#!/bin/bash\ncargo build 2>&1 | tee build.log\n")?;
    write(
        root,
        "linuxdaemon.service",
        "[Unit]\nDescription=linuxdaemon service for systemd\n[Service]\nExecStart=/usr/bin/linuxdaemon\n[Install]\nWantedBy=multi-user.target\n",
    )?;
    write(root, "Makefile", "all:\n\tcargo build --release\n")?;
    write(root, "crontab.txt", "*/5 * * * * root /usr/bin/linuxdaemon --sweep\n")?;
    Ok(())
}

/// Clean, portable Rust library: no platform-specific surface.
pub fn portable_repo(root: &Path) -> io::Result<()> {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"portablelib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    write(
        root,
        "src/lib.rs",
        r#"//! A portable library.
use std::path::PathBuf;

/// Joins a relative config name onto a base directory.
pub fn config_path(base: &std::path::Path, name: &str) -> PathBuf {
    base.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn joins() {
        assert_eq!(config_path(std::path::Path::new("x"), "y.toml"), std::path::Path::new("x").join("y.toml"));
    }
}
"#,
    )?;
    Ok(())
}

/// Repo whose only suspicious surface is a `git` invocation: classified
/// Tooling, Info severity — never a blocker.
pub fn git_invocation_repo(root: &Path) -> io::Result<()> {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"gitwrapper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    write(
        root,
        "src/main.rs",
        r#"use std::process::Command;

fn main() {
    let status = Command::new("git").arg("status").status().unwrap();
    println!("{:?}", status);
}
"#,
    )?;
    Ok(())
}
