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
_STAGE_SCRIPT = _ROOT / "scripts" / "release-stage-github-upload.sh"
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
    if match is not None:
        return match.group(1)
    dynamic = re.search(
        r"uses: softprops/action-gh-release@[^\n]+\n\s+with:.*?\n\s+files:\s*\$\{\{",
        workflow,
        re.DOTALL,
    )
    assert dynamic is not None, "softprops/action-gh-release files input not found"
    return ""


def test_release_workflow_gh_release_files_have_no_hash_rename_syntax() -> None:
    files_block = _gh_release_files_block(_release_workflow_text())
    for line in files_block.splitlines():
        entry = line.strip()
        if not entry:
            continue
        assert "#" not in entry, f"unsupported path#name syntax in files entry: {entry}"


def test_release_workflow_gh_release_uses_explicit_upload_list() -> None:
    workflow = _release_workflow_text()
    assert "release-list-github-upload-files.sh" in workflow
    assert "fail_on_unmatched_files: true" in workflow
    assert "github-upload/*" not in workflow


def test_release_workflow_stages_archives_before_draft_release() -> None:
    workflow = _release_workflow_text()
    stage_idx = workflow.index("release-stage-github-upload.sh")
    draft_idx = workflow.index("Create draft GitHub Release")
    assert stage_idx < draft_idx


def test_release_workflow_builds_archive_on_matrix_runners() -> None:
    workflow = _release_workflow_text()
    assert "release-build-platform-archive.sh" in workflow
    assert "release-list-github-upload-files.sh" in workflow
    assert "fail_on_unmatched_files: true" in workflow


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


def test_release_workflow_build_binary_denies_rustc_warnings() -> None:
    workflow = _release_workflow_text()
    build_job = re.search(
        r"build-binary:.*?(?=\n  binary-slsa-provenance:)",
        workflow,
        re.DOTALL,
    )
    assert build_job is not None
    assert "RUSTFLAGS: -Dwarnings" in build_job.group(0)


def test_release_workflow_archive_upload_uses_relative_path() -> None:
    """upload-artifact on Windows does not resolve MSYS absolute paths."""
    workflow = _release_workflow_text()
    build_job = re.search(
        r"build-binary:.*?(?=\n  binary-slsa-provenance:)",
        workflow,
        re.DOTALL,
    )
    assert build_job is not None
    assert 'archive_path=dist-archive/${archive_name}' in build_job.group(0)
    assert "echo \"archive_path=${archive_path}\"" not in build_job.group(0)


def test_release_workflow_skips_download_layout_restore() -> None:
    workflow = _release_workflow_text()
    assert "release-restore-download-layout.sh" not in workflow


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
    """Legacy restore still supports older raw-asset releases."""
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


def test_release_stage_github_upload_creates_versioned_archive_names(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "release-artifacts"
    version = "3.1.4"
    binary = tmp_path / "vlz"
    binary.write_bytes(b"linux")
    binary.chmod(0o755)
    for platform in ("linux-x86_64", "macos-aarch64"):
        out_dir = artifacts / f"vlz-{platform}"
        out_dir.mkdir(parents=True)
        subprocess.run(
            [
                str(_ROOT / "scripts" / "release-build-platform-archive.sh"),
                "--platform",
                platform,
                "--version",
                version,
                "--binary",
                str(binary),
                "--repo-root",
                str(_ROOT),
                "--output-dir",
                str(out_dir),
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        archive = out_dir / f"vlz-{version}-{platform}.tar.gz"
        (out_dir / f"{archive.name}.sigstore.json").write_bytes(b"sig")
        (out_dir / f"{archive.name}.intoto.jsonl").write_bytes(b"att")

    exe = tmp_path / "vlz.exe"
    exe.write_bytes(b"windows")
    win_dir = artifacts / "vlz-windows-x86_64"
    win_dir.mkdir(parents=True)
    subprocess.run(
        [
            str(_ROOT / "scripts" / "release-build-platform-archive.sh"),
            "--platform",
            "windows-x86_64",
            "--version",
            version,
            "--binary",
            str(exe),
            "--repo-root",
            str(_ROOT),
            "--output-dir",
            str(win_dir),
        ],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    win_archive = win_dir / f"vlz-{version}-windows-x86_64.zip"
    (win_dir / f"{win_archive.name}.sigstore.json").write_bytes(b"sig")
    (win_dir / f"{win_archive.name}.intoto.jsonl").write_bytes(b"att")

    proc = subprocess.run(
        [str(_STAGE_SCRIPT), str(artifacts), version],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout

    upload_dir = artifacts / "github-upload"
    assert (upload_dir / f"vlz-{version}-linux-x86_64.tar.gz").is_file()
    assert (upload_dir / f"vlz-{version}-macos-aarch64.tar.gz").is_file()
    assert (upload_dir / f"vlz-{version}-windows-x86_64.zip").is_file()
    assert (upload_dir / f"vlz-{version}-linux-x86_64.tar.gz.sigstore.json").is_file()


def test_release_restore_download_layout_legacy_raw_asset_names(
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


def _job_block(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"\n  {re.escape(job_id)}:.*?(?=\n  [a-zA-Z0-9_-]+:|\Z)",
        workflow,
        re.DOTALL,
    )
    assert match is not None, f"missing job {job_id}"
    return match.group(0)


def test_create_draft_job_does_not_publish() -> None:
    workflow = _release_workflow_text()
    block = _job_block(workflow, "create-draft")
    assert "draft: true" in block
    assert "--draft=false" not in block
    assert "wait-obs-builds" not in block.split("runs-on:")[0]


def test_cli_contract_draft_can_download_draft_archives() -> None:
    """GITHUB_TOKEN needs contents: write to see draft Releases."""
    workflow = _release_workflow_text()
    block = _job_block(workflow, "cli-contract-draft")
    header = block.split("steps:")[0]
    assert "fail-fast: false" in header
    assert "contents: write" in header
    assert "ci-install-vlz-release-archive.sh" in block
    assert "CLI_CONTRACT_MODE" in block


def test_cli_contract_draft_builder_regex_avoids_msys_backslash_dots() -> None:
    """Git-bash on Windows rewrites \\. in env values to /.; use [.] instead."""
    workflow = _release_workflow_text()
    block = _job_block(workflow, "cli-contract-draft")
    assert "EXPECTED_BUILDER_REGEX: ^https://github[.]com/" in block
    assert "/[.]github/workflows/release[.]yml@" in block
    env_line = next(
        line
        for line in block.splitlines()
        if "EXPECTED_BUILDER_REGEX:" in line
    )
    assert r"\." not in env_line


def test_release_workflow_slsa_regex_avoids_msys_backslash_dots() -> None:
    workflow = _release_workflow_text()
    regex_match = re.search(
        r"SLSA_GENERATOR_BUILDER_REGEX:\s*(.+)$",
        workflow,
        re.MULTILINE,
    )
    assert regex_match is not None
    assert r"\." not in regex_match.group(1)
    assert "github[.]com" in regex_match.group(1)


def test_publish_release_needs_cli_and_obs() -> None:
    workflow = _release_workflow_text()
    block = _job_block(workflow, "publish-release")
    header = block.split("steps:")[0]
    assert "cli-contract-draft" in header
    assert "wait-obs-builds" in header
    assert "contents: write" in header
    assert "--draft=false" in block
    assert "success()" in header
    assert "--draft=false" in block


def test_publish_release_sets_repo_without_checkout() -> None:
    """gh release edit needs --repo when the job has no git checkout."""
    workflow = _release_workflow_text()
    block = _job_block(workflow, "publish-release")
    assert "actions/checkout@" not in block
    assert 'gh release edit "${TAG}" --repo "${GITHUB_REPOSITORY}" --draft=false' in block

