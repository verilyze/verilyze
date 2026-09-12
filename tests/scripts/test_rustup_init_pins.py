# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/rustup_init_pins.py."""

import sys
from pathlib import Path

import pytest

from scripts import rustup_init_pins
from scripts.rustup_init_pins import (
    DOCKERFILE_REL,
    fetch_archive_sha256,
    get_repo_root,
    main,
    parse_rustup_version,
    replace_sha256_args,
    sync_dockerfile_sha256s,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()

_DOCKERFILE_FIXTURE = """\
# header
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256_AMD64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ARG RUSTUP_INIT_SHA256_ARM64=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

FROM ubuntu:26.04@sha256:deadbeef
ARG RUSTUP_VERSION
ARG RUSTUP_INIT_SHA256_AMD64
ARG RUSTUP_INIT_SHA256_ARM64
"""


class TestParseRustupVersion:
    def test_parse_rustup_version_reads_arg(self) -> None:
        assert parse_rustup_version(_DOCKERFILE_FIXTURE) == "1.29.1"

    def test_parse_rustup_version_missing_raises(self) -> None:
        with pytest.raises(SystemExit, match="RUSTUP_VERSION"):
            parse_rustup_version("FROM scratch\n")


class TestReplaceSha256Args:
    def test_replace_sha256_args_updates_both_pins(self) -> None:
        updated = replace_sha256_args(
            _DOCKERFILE_FIXTURE,
            amd64="1111111111111111111111111111111111111111111111111111111111111111",
            arm64="2222222222222222222222222222222222222222222222222222222222222222",
        )
        assert (
            "ARG RUSTUP_INIT_SHA256_AMD64="
            "1111111111111111111111111111111111111111111111111111111111111111"
        ) in updated
        assert (
            "ARG RUSTUP_INIT_SHA256_ARM64="
            "2222222222222222222222222222222222222222222222222222222222222222"
        ) in updated
        assert (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            not in updated
        )

    def test_replace_sha256_args_rejects_non_hex(self) -> None:
        with pytest.raises(SystemExit, match="SHA-256"):
            replace_sha256_args(
                _DOCKERFILE_FIXTURE,
                amd64="not-a-hash",
                arm64="x" * 64,
            )


class TestFetchArchiveSha256:
    def test_fetch_archive_sha256_parses_first_field(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"deadbeefcafef00d" + b"0" * 48 + b" *./rustup-init\n"

        digest = fetch_archive_sha256(
            "1.29.1",
            "x86_64-unknown-linux-gnu",
            opener=lambda _url, timeout=30: _Resp(),
        )
        assert digest == "deadbeefcafef00d" + "0" * 48

    def test_fetch_archive_sha256_rejects_malformed(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"not-a-checksum\n"

        with pytest.raises(SystemExit, match="checksum"):
            fetch_archive_sha256(
                "1.29.1",
                "x86_64-unknown-linux-gnu",
                opener=lambda _url, timeout=30: _Resp(),
            )


class TestGetRepoRoot:
    def test_get_repo_root_points_at_workspace(self) -> None:
        root = get_repo_root()
        assert (root / "scripts" / "rustup_init_pins.py").is_file()


class TestSyncDockerfileSha256s:
    def test_sync_updates_stale_pins(self, tmp_path: Path) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")

        def fake_fetch(version: str, triple: str, **_kwargs: object) -> str:
            assert version == "1.29.1"
            if "x86_64" in triple:
                return "c" * 64
            return "d" * 64

        changed = sync_dockerfile_sha256s(tmp_path, fetch=fake_fetch)
        assert changed is True
        text = dockerfile.read_text(encoding="utf-8")
        assert f"ARG RUSTUP_INIT_SHA256_AMD64={'c' * 64}" in text
        assert f"ARG RUSTUP_INIT_SHA256_ARM64={'d' * 64}" in text

    def test_sync_noop_when_already_current(self, tmp_path: Path) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        current = replace_sha256_args(
            _DOCKERFILE_FIXTURE,
            amd64="c" * 64,
            arm64="d" * 64,
        )
        dockerfile.write_text(current, encoding="utf-8")

        def fake_fetch(_version: str, triple: str, **_kwargs: object) -> str:
            if "x86_64" in triple:
                return "c" * 64
            return "d" * 64

        changed = sync_dockerfile_sha256s(tmp_path, fetch=fake_fetch)
        assert changed is False


class TestMain:
    def test_main_check_detects_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")
        monkeypatch.setattr(
            rustup_init_pins, "get_repo_root", lambda: tmp_path
        )
        monkeypatch.setattr(
            rustup_init_pins,
            "fetch_archive_sha256",
            lambda _v, triple, **_k: (
                "c" * 64 if "x86_64" in triple else "d" * 64
            ),
        )
        monkeypatch.setattr(sys, "argv", ["rustup_init_pins.py", "--check"])
        assert main() == 1

    def test_main_writes_updated_pins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")
        monkeypatch.setattr(
            rustup_init_pins, "get_repo_root", lambda: tmp_path
        )
        monkeypatch.setattr(
            rustup_init_pins,
            "fetch_archive_sha256",
            lambda _v, triple, **_k: (
                "c" * 64 if "x86_64" in triple else "d" * 64
            ),
        )
        monkeypatch.setattr(sys, "argv", ["rustup_init_pins.py"])
        assert main() == 0
        text = dockerfile.read_text(encoding="utf-8")
        assert f"ARG RUSTUP_INIT_SHA256_AMD64={'c' * 64}" in text


class TestCommittedDockerfile:
    def test_committed_dockerfile_sha256s_match_archive(self) -> None:
        """Live check: committed pins must match static.rust-lang.org."""
        assert sync_dockerfile_sha256s(_ROOT, check=True) is False
