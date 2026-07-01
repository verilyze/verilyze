// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fake `pip` / `python` scripts on `PATH` for resolver unit tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Workspace `target/fake-toolchain` (root `/target` is gitignored; not REUSE-scanned).
fn fake_toolchain_base() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../target/fake-toolchain")
}

static FAKE_TOOLCHAIN_ENV_LOCK: Mutex<()> = Mutex::new(());
static FAKE_TOOLCHAIN_SESSION: OnceLock<tempfile::TempDir> = OnceLock::new();
static FAKE_TOOLCHAIN_SLOT: AtomicUsize = AtomicUsize::new(0);

/// A temporary directory prepended to `PATH` with fake toolchain binaries.
pub struct FakeToolchainPath {
    _slot: PathBuf,
    venv_tmp: String,
    /// When true, `PATH` is only the slot (no host `pip`/`python`).
    isolate_path: bool,
}

impl FakeToolchainPath {
    /// Run `f` with fake `PATH` and an exec-capable `TMPDIR` for ephemeral venvs.
    pub fn with_path<F, R>(self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = FAKE_TOOLCHAIN_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let path_var = if self.isolate_path {
            self._slot.to_string_lossy().into_owned()
        } else {
            prepend_path(&self._slot)
        };
        temp_env::with_vars(
            [
                ("PATH", Some(path_var.as_str())),
                ("XDG_RUNTIME_DIR", None::<&str>),
                ("TMPDIR", Some(self.venv_tmp.as_str())),
            ],
            f,
        )
    }

    /// Writable project directory beside the fake toolchain (for manifest fixtures).
    pub fn project_dir(&self) -> PathBuf {
        let project = self._slot.join("project");
        std::fs::create_dir_all(&project).expect("project dir");
        project
    }
}

fn fake_toolchain_session() -> &'static tempfile::TempDir {
    FAKE_TOOLCHAIN_SESSION.get_or_init(|| {
        let base = fake_toolchain_base();
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("mkdir fake-toolchain base");
        tempfile::tempdir_in(base).expect("tempdir in target")
    })
}

fn allocate_toolchain_slot() -> PathBuf {
    let n = FAKE_TOOLCHAIN_SLOT.fetch_add(1, Ordering::Relaxed);
    let slot = fake_toolchain_session().path().join(format!("slot-{n}"));
    std::fs::create_dir_all(&slot).expect("toolchain slot");
    slot
}

#[cfg(unix)]
fn fake_toolchain_path(slot: PathBuf) -> FakeToolchainPath {
    let venv_tmp = slot.join("venv-tmp");
    std::fs::create_dir_all(&venv_tmp).expect("mkdir venv tmp");
    FakeToolchainPath {
        _slot: slot,
        venv_tmp: venv_tmp.to_string_lossy().into_owned(),
        isolate_path: false,
    }
}

#[cfg(unix)]
fn write_executable(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write script");
    let mut perms = std::fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod");
}

#[cfg(unix)]
fn prepend_path(dir: &Path) -> String {
    const STANDARD_PATH: &str =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let ambient = std::env::var("PATH").unwrap_or_default();
    let tail = if ambient.is_empty() {
        STANDARD_PATH.to_string()
    } else {
        format!("{STANDARD_PATH}:{ambient}")
    };
    format!("{}:{tail}", dir.display())
}

#[cfg(unix)]
fn install_pip_script(dir: &Path, body: &str) {
    write_executable(&dir.join("pip"), body);
    write_executable(&dir.join("pip3"), body);
}

#[cfg(unix)]
fn install_pip_too_old_stub(dir: &Path) {
    let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 24.0 from /fake"
  exit 0
fi
exit 1
"#;
    install_pip_script(dir, script);
}

/// Skip `-q` / `--quiet` before the `lock` subcommand (matches production argv).
#[cfg(unix)]
const FAKE_PIP_SKIP_QUIET: &str = r#"
if [ "$1" = "-q" ] || [ "$1" = "--quiet" ]; then
  shift
fi
"#;

/// Fake pip >= 25.1 whose `lock` subcommand prints `pylock_body` on stdout.
/// Increments `counter_path` on each `lock` invocation when provided.
#[cfg(unix)]
pub fn fake_pip_lock_counting(
    pylock_body: &str,
    counter_path: &Path,
) -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let counter = counter_path.to_string_lossy().into_owned();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 25.1.1 from /fake"
  exit 0
fi
{FAKE_PIP_SKIP_QUIET}
if [ "$1" = "lock" ]; then
  n=0
  if [ -f "{counter}" ]; then
    n=$(cat "{counter}")
  fi
  echo $((n + 1)) > "{counter}"
  cat <<'PYLOCK'
{pylock_body}
PYLOCK
  exit 0
fi
exit 1
"#
    );
    install_pip_script(&slot, &script);
    fake_toolchain_path(slot)
}

/// Fake pip >= 25.1 whose `lock` subcommand prints `pylock_body` on stdout.
#[cfg(unix)]
pub fn fake_pip_lock_success(pylock_body: &str) -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 25.1.1 from /fake"
  exit 0
fi
{FAKE_PIP_SKIP_QUIET}
if [ "$1" = "lock" ]; then
  cat <<'PYLOCK'
{pylock_body}
PYLOCK
  exit 0
fi
exit 1
"#
    );
    install_pip_script(&slot, &script);
    fake_toolchain_path(slot)
}

/// Fake pip whose `lock` subcommand exits non-zero.
#[cfg(unix)]
pub fn fake_pip_lock_failure() -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 25.1.1 from /fake"
  exit 0
fi
{FAKE_PIP_SKIP_QUIET}
if [ "$1" = "lock" ]; then
  echo "pip lock failed" >&2
  exit 1
fi
exit 1
"#
    );
    install_pip_script(&slot, &script);
    fake_toolchain_path(slot)
}

/// Fake pip 24.x (too old for `pip lock`).
#[cfg(unix)]
pub fn fake_pip_too_old() -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 24.0 from /fake"
  exit 0
fi
exit 1
"#;
    install_pip_script(&slot, script);
    fake_toolchain_path(slot)
}

/// Fake pip whose `lock` subcommand succeeds with empty stdout.
#[cfg(unix)]
pub fn fake_pip_lock_empty_output() -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "pip 25.1.1 from /fake"
  exit 0
fi
{FAKE_PIP_SKIP_QUIET}
if [ "$1" = "lock" ]; then
  exit 0
fi
exit 1
"#
    );
    install_pip_script(&slot, &script);
    fake_toolchain_path(slot)
}

/// Fake pip whose `lock` subcommand prints pylock with no packages.
#[cfg(unix)]
pub fn fake_pip_lock_no_packages() -> FakeToolchainPath {
    fake_pip_lock_success("lock-version = \"1.0\"\npackages = []\n")
}

/// Fake python that creates a venv whose pip install/freeze behave as configured.
/// Includes pip 24.x stubs so tests do not pick up the host `pip`.
#[cfg(unix)]
pub fn fake_python_venv(
    install_exit: i32,
    freeze_stdout: &str,
    freeze_exit: i32,
    venv_exit: i32,
) -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let script = format!(
        r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "Python 3.12.0"
  exit 0
fi
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  if [ {venv_exit} -ne 0 ]; then
    exit {venv_exit}
  fi
  VENV="$3"
  /usr/bin/mkdir -p "$VENV/bin"
  /usr/bin/cat > "$VENV/bin/pip" <<'INNER'
#!/bin/sh
if [ "$1" = "install" ]; then
  exit {install_exit}
fi
if [ "$1" = "freeze" ]; then
  printf '%s\n' "{freeze_stdout}"
  exit {freeze_exit}
fi
exit 1
INNER
  /usr/bin/chmod +x "$VENV/bin/pip"
  exit 0
fi
exit 1
"#
    );
    write_executable(&slot.join("python3"), &script);
    write_executable(&slot.join("python"), &script);
    install_pip_too_old_stub(&slot);
    fake_toolchain_path(slot)
}

/// Empty `PATH` (no pip/python).
pub fn empty_path() -> FakeToolchainPath {
    let slot = allocate_toolchain_slot();
    let venv_tmp = slot.join("venv-tmp");
    std::fs::create_dir_all(&venv_tmp).expect("mkdir venv tmp");
    FakeToolchainPath {
        _slot: slot,
        venv_tmp: venv_tmp.to_string_lossy().into_owned(),
        isolate_path: true,
    }
}
