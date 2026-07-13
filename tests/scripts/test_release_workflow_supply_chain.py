# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for release signing and provenance workflow coverage."""

import re
import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_RESTORE_SCRIPT = _ROOT / "scripts" / "release-restore-download-layout.sh"
_STAGE_SCRIPT = _ROOT / "scripts" / "release-stage-github-binary-upload.sh"
_ROUNDTRIP_SCRIPT = _ROOT / "scripts" / "release-verify-upload-roundtrip.sh"
_RELEASE_WORKFLOW = _ROOT / ".github" / "workflows" / "release.yml"
_SLSA_PIN_SHA = "f7dd8c54c2067bafc12ca7a55595d5ee9b75204a"


def _release_workflow_text() -> str:
    return _RELEASE_WORKFLOW.read_text(encoding="utf-8")


def _gh_release_files_block(workflow: str) -> str:
    match = re.search(
        r"uses: softprops/action-gh-release@[^\n]+\n\s+with:.*?\n\s+files: \|(.*?)(?:\n\s{6}\S|\n\s{4}\S)",
        workflow,
        re.DOTALL,
    )
    assert match is not None, "softprops/action-gh-release files block not found"
    return match.group(1)


def test_release_workflow_gh_release_files_have_no_hash_rename_syntax() -> None:
    files_block = _gh_release_files_block(_release_workflow_text())
    for line in files_block.splitlines():
        entry = line.strip()
        if not entry:
            continue
        assert "#" not in entry, f"unsupported path#name syntax in files entry: {entry}"


def test_release_workflow_stages_binaries_before_draft_release() -> None:
    workflow = _release_workflow_text()
    stage_idx = workflow.index("release-stage-github-binary-upload.sh")
    draft_idx = workflow.index("Create draft GitHub Release")
    assert stage_idx < draft_idx


def test_release_workflow_slsa_regex_includes_renovate_pin_sha() -> None:
    workflow = _release_workflow_text()
    assert _SLSA_PIN_SHA in workflow
    regex_match = re.search(
        r"SLSA_GENERATOR_BUILDER_REGEX:\s*(.+)$",
        workflow,
        re.MULTILINE,
    )
    assert regex_match is not None
    assert _SLSA_PIN_SHA in regex_match.group(1)


def test_release_workflow_binary_slsa_job_has_contents_write() -> None:
    workflow = _release_workflow_text()
    job_match = re.search(
        r"binary-slsa-provenance:.*?(?=\n  \S)",
        workflow,
        re.DOTALL,
    )
    assert job_match is not None
    assert "contents: write" in job_match.group(0)


def test_release_workflow_macos_hash_uses_portable_base64() -> None:
    workflow = _release_workflow_text()
    build_job = re.search(
        r"build-binary:.*?(?=\n  binary-slsa-provenance:)",
        workflow,
        re.DOTALL,
    )
    assert build_job is not None
    assert "base64 < checksum" in build_job.group(0)


def test_release_verify_upload_roundtrip_script_succeeds() -> None:
    proc = subprocess.run(
        [str(_ROUNDTRIP_SCRIPT)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "round-trip" in (proc.stderr + proc.stdout).lower()


def test_release_backfill_workflow_removed() -> None:
    backfill = _ROOT / ".github" / "workflows" / "release-backfill-metadata.yml"
    assert not backfill.exists()


def test_release_restore_download_layout_uses_rpm_x86_64_path(tmp_path: Path) -> None:
    download_dir = tmp_path / "draft-verify"
    download_dir.mkdir()
    (download_dir / "vlz").write_bytes(b"vlz-binary")
    (download_dir / "vlz_0.1.0_amd64.deb").write_bytes(b"deb-pkg")
    (download_dir / "vlz-0.1.0-1.x86_64.rpm").write_bytes(b"rpm-pkg")

    proc = subprocess.run(
        [str(_RESTORE_SCRIPT), str(download_dir)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (download_dir / "rpm-package" / "x86_64" / "vlz-0.1.0-1.x86_64.rpm").is_file()


def test_release_stage_github_binary_upload_creates_flat_asset_names(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "release-artifacts"
    for rel_path, payload in (
        ("vlz-linux-x86_64/vlz", b"linux"),
        ("vlz-macos-aarch64/vlz", b"macos"),
        ("vlz-windows-x86_64/vlz.exe", b"windows"),
    ):
        path = artifacts / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.with_suffix(path.suffix + ".sigstore.json").write_bytes(
            f"{rel_path}-sig".encode()
        )
        path.with_suffix(path.suffix + ".intoto.jsonl").write_bytes(
            f"{rel_path}-att".encode()
        )

    proc = subprocess.run(
        [str(_STAGE_SCRIPT), str(artifacts)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    upload_dir = artifacts / "github-upload"
    assert (upload_dir / "vlz-linux-x86_64").read_bytes() == b"linux"
    assert (upload_dir / "vlz-macos-aarch64").read_bytes() == b"macos"
    assert (upload_dir / "vlz-windows-x86_64.exe").read_bytes() == b"windows"
    assert (upload_dir / "vlz-linux-x86_64.sigstore.json").is_file()
    assert (upload_dir / "vlz-macos-aarch64.intoto.jsonl").is_file()


def test_release_workflow_stages_flat_binary_upload_paths() -> None:
    workflow = _RELEASE_WORKFLOW.read_text(encoding="utf-8")
    assert "release-stage-github-binary-upload.sh" in workflow
    assert "release-artifacts/github-upload/vlz-linux-x86_64" in workflow
    assert "#vlz-linux-x86_64" not in workflow


def test_release_restore_download_layout_cross_platform_asset_names(
    tmp_path: Path,
) -> None:
    download_dir = tmp_path / "draft-verify"
    download_dir.mkdir()
    (download_dir / "vlz-linux-x86_64").write_bytes(b"linux")
    (download_dir / "vlz-linux-x86_64.sigstore.json").write_bytes(b"linux-sig")
    (download_dir / "vlz-macos-aarch64").write_bytes(b"macos")
    (download_dir / "vlz-macos-aarch64.sigstore.json").write_bytes(b"macos-sig")
    (download_dir / "vlz-windows-x86_64.exe").write_bytes(b"windows")
    (download_dir / "vlz-windows-x86_64.exe.sigstore.json").write_bytes(b"win-sig")

    proc = subprocess.run(
        [str(_RESTORE_SCRIPT), str(download_dir)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (download_dir / "vlz-linux-x86_64" / "vlz").read_bytes() == b"linux"
    assert (download_dir / "vlz-macos-aarch64" / "vlz").read_bytes() == b"macos"
    assert (
        download_dir / "vlz-windows-x86_64" / "vlz.exe"
    ).read_bytes() == b"windows"


def test_release_read_workspace_version_script_matches_cargo_toml() -> None:
    script = _ROOT / "scripts" / "release-read-workspace-version.sh"
    cargo = _ROOT / "Cargo.toml"
    assert script.is_file()
    proc = subprocess.run(
        [str(script), str(cargo)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    version_line = next(
        line for line in cargo.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("version = ")
    )
    cargo_version = version_line.split("=", 1)[1].strip().strip('"')
    assert proc.stdout.strip() == cargo_version
