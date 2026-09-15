// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unix test helpers: write an executable stub via rename, then retry exec
//! while Linux reports ETXTBSY.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

const WRITE_TMP_EXTENSION: &str = "write-tmp";
const STUB_EXEC_READY_ATTEMPTS: u32 = 8;
const STUB_EXEC_READY_DELAY: Duration = Duration::from_millis(5);

/// Write an executable stub via rename-before-exec (avoids Linux ETXTBSY
/// when the final path is still open for write), then retry spawn until
/// the kernel accepts exec.
pub(crate) fn write_executable(path: &Path, body: &str) {
    write_stub_script(path, body);
    wait_stub_exec_ready(path);
}

fn write_stub_script(path: &Path, body: &str) {
    let tmp = path.with_extension(WRITE_TMP_EXTENSION);
    std::fs::write(&tmp, body).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// Retry until the stub can be spawned (exit status is ignored).
///
/// Probe with `spawn` + `kill` so payloads such as `exec sleep 30` do not
/// block the helper.
fn wait_stub_exec_ready(path: &Path) {
    let mut last_err = None;
    for _ in 0..STUB_EXEC_READY_ATTEMPTS {
        match std::process::Command::new(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                    || e.raw_os_error() == Some(26) =>
            {
                last_err = Some(e);
                std::thread::sleep(STUB_EXEC_READY_DELAY);
            }
            Err(e) => panic!("spawn {}: {e}", path.display()),
        }
    }
    panic!(
        "spawn {} still busy after retries: {last_err:?}",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_executable_replaces_tmp_and_is_spawnable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stub");
        write_executable(&path, "#!/bin/sh\nexit 0\n");
        assert!(path.is_file());
        assert!(!path.with_extension(WRITE_TMP_EXTENSION).exists());
        let status = std::process::Command::new(&path).status().unwrap();
        assert!(status.success());
    }

    #[test]
    fn wait_stub_exec_ready_retries_while_text_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stub");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let held =
            std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let path_for_wait = path.clone();
        let waiter = std::thread::spawn(move || {
            wait_stub_exec_ready(&path_for_wait);
        });
        std::thread::sleep(STUB_EXEC_READY_DELAY.saturating_mul(2));
        drop(held);
        waiter.join().expect("ETXTBSY waiter thread");
    }
}
