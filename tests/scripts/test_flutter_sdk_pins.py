# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for scripts/flutter_sdk_pins.py."""

import json
import re
import runpy
import sys
import urllib.request
from pathlib import Path

import pytest

from scripts import flutter_sdk_pins
from scripts.flutter_sdk_pins import (
    DOCKERFILE_REL,
    FlutterReleasePins,
    fetch_dart_arm64_sha256,
    fetch_flutter_linux_pins,
    get_repo_root,
    main,
    parse_flutter_version,
    replace_sdk_pin_args,
    sync_dockerfile_pins,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()

_DOCKERFILE_FIXTURE = """\
# header
ARG FLUTTER_VERSION=3.47.7
ARG FLUTTER_SHA256_AMD64=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ARG DART_SDK_VERSION=3.0.0
ARG DART_SHA256_ARM64=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

FROM ubuntu:26.04@sha256:deadbeef
ARG FLUTTER_VERSION
ARG FLUTTER_SHA256_AMD64
ARG DART_SDK_VERSION
ARG DART_SHA256_ARM64
"""


class TestParseFlutterVersion:
    def test_parse_flutter_version_reads_arg(self) -> None:
        assert parse_flutter_version(_DOCKERFILE_FIXTURE) == "3.47.7"

    def test_parse_flutter_version_missing_raises(self) -> None:
        with pytest.raises(SystemExit, match="FLUTTER_VERSION"):
            parse_flutter_version("FROM scratch\n")


class TestReplaceSdkPinArgs:
    def test_replace_sdk_pin_args_updates_all_pins(self) -> None:
        updated = replace_sdk_pin_args(
            _DOCKERFILE_FIXTURE,
            FlutterReleasePins(
                flutter_sha256_amd64="1" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="2" * 64,
            ),
        )
        assert f"ARG FLUTTER_SHA256_AMD64={'1' * 64}" in updated
        assert "ARG DART_SDK_VERSION=3.13.5" in updated
        assert f"ARG DART_SHA256_ARM64={'2' * 64}" in updated
        assert (
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            not in updated
        )

    def test_replace_sdk_pin_args_rejects_non_hex_flutter(self) -> None:
        with pytest.raises(SystemExit, match="SHA-256"):
            replace_sdk_pin_args(
                _DOCKERFILE_FIXTURE,
                FlutterReleasePins(
                    flutter_sha256_amd64="not-a-hash",
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="x" * 64,
                ),
            )

    def test_replace_sdk_pin_args_rejects_non_hex_dart(self) -> None:
        with pytest.raises(SystemExit, match="SHA-256"):
            replace_sdk_pin_args(
                _DOCKERFILE_FIXTURE,
                FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="not-a-hash",
                ),
            )

    def test_replace_sdk_pin_args_rejects_bad_dart_version(self) -> None:
        with pytest.raises(SystemExit, match="dart_sdk_version"):
            replace_sdk_pin_args(
                _DOCKERFILE_FIXTURE,
                FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="not-semver",
                    dart_sha256_arm64="d" * 64,
                ),
            )

    def test_replace_sdk_pin_args_missing_flutter_sha_raises(self) -> None:
        text = "\n".join(
            line
            for line in _DOCKERFILE_FIXTURE.splitlines()
            if "FLUTTER_SHA256_AMD64=" not in line
        )
        with pytest.raises(SystemExit, match="FLUTTER_SHA256_AMD64"):
            replace_sdk_pin_args(
                text,
                FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="d" * 64,
                ),
            )

    def test_replace_sdk_pin_args_missing_dart_version_raises(self) -> None:
        text = "\n".join(
            line
            for line in _DOCKERFILE_FIXTURE.splitlines()
            if "DART_SDK_VERSION=" not in line
        )
        with pytest.raises(SystemExit, match="DART_SDK_VERSION"):
            replace_sdk_pin_args(
                text,
                FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="d" * 64,
                ),
            )

    def test_replace_sdk_pin_args_missing_dart_sha_raises(self) -> None:
        text = "\n".join(
            line
            for line in _DOCKERFILE_FIXTURE.splitlines()
            if "DART_SHA256_ARM64=" not in line
        )
        with pytest.raises(SystemExit, match="DART_SHA256_ARM64"):
            replace_sdk_pin_args(
                text,
                FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="d" * 64,
                ),
            )


class TestFetchFlutterLinuxPins:
    def test_fetch_flutter_linux_pins_reads_stable_release(self) -> None:
        payload = {
            "base_url": "https://example.invalid/releases",
            "releases": [
                {
                    "channel": "stable",
                    "version": "3.47.7",
                    "dart_sdk_version": "3.13.5",
                    "archive": "stable/linux/flutter_linux_3.47.7-stable.tar.xz",
                    "sha256": "a" * 64,
                }
            ],
        }

        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(payload).encode("utf-8")

        pins = fetch_flutter_linux_pins(
            "3.47.7",
            opener=lambda _url, timeout=30: _Resp(),
        )
        assert pins.flutter_sha256_amd64 == "a" * 64
        assert pins.dart_sdk_version == "3.13.5"
        assert pins.archive_path == (
            "stable/linux/flutter_linux_3.47.7-stable.tar.xz"
        )

    def test_fetch_flutter_linux_pins_missing_version_raises(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"releases":[]}'

        with pytest.raises(SystemExit, match="3.47.7"):
            fetch_flutter_linux_pins(
                "3.47.7",
                opener=lambda _url, timeout=30: _Resp(),
            )

    def test_fetch_flutter_linux_pins_rejects_bad_index(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"releases":"nope"}'

        with pytest.raises(SystemExit, match="releases list"):
            fetch_flutter_linux_pins(
                "3.47.7",
                opener=lambda _url, timeout=30: _Resp(),
            )

    def test_fetch_flutter_linux_pins_skips_noise_and_validates_fields(
        self,
    ) -> None:
        payload = {
            "releases": [
                "skip-me",
                {"channel": "beta", "version": "3.47.7"},
                {"channel": "stable", "version": "9.9.9"},
                {
                    "channel": "stable",
                    "version": "3.47.7",
                    "sha256": "bad",
                    "dart_sdk_version": "3.13.5",
                    "archive": "x.tar.xz",
                },
            ]
        }

        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(payload).encode("utf-8")

        with pytest.raises(SystemExit, match="sha256"):
            fetch_flutter_linux_pins(
                "3.47.7",
                opener=lambda _url, timeout=30: _Resp(),
            )

    def test_fetch_flutter_linux_pins_rejects_bad_dart_version(self) -> None:
        payload = {
            "releases": [
                {
                    "channel": "stable",
                    "version": "3.47.7",
                    "sha256": "a" * 64,
                    "dart_sdk_version": "nope",
                    "archive": "x.tar.xz",
                }
            ]
        }

        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(payload).encode("utf-8")

        with pytest.raises(SystemExit, match="dart_sdk_version"):
            fetch_flutter_linux_pins(
                "3.47.7",
                opener=lambda _url, timeout=30: _Resp(),
            )

    def test_fetch_flutter_linux_pins_rejects_missing_archive(self) -> None:
        payload = {
            "releases": [
                {
                    "channel": "stable",
                    "version": "3.47.7",
                    "sha256": "a" * 64,
                    "dart_sdk_version": "3.13.5",
                    "archive": "",
                }
            ]
        }

        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(payload).encode("utf-8")

        with pytest.raises(SystemExit, match="archive"):
            fetch_flutter_linux_pins(
                "3.47.7",
                opener=lambda _url, timeout=30: _Resp(),
            )


class TestFetchDartArm64Sha256:
    def test_fetch_dart_arm64_sha256_parses_first_field(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"deadbeefcafef00d" + b"0" * 48 + b" *dartsdk.zip\n"

        digest = fetch_dart_arm64_sha256(
            "3.13.5",
            opener=lambda _url, timeout=30: _Resp(),
        )
        assert digest == "deadbeefcafef00d" + "0" * 48

    def test_fetch_dart_arm64_sha256_rejects_malformed(self) -> None:
        class _Resp:
            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"not-a-checksum\n"

        with pytest.raises(SystemExit, match="checksum"):
            fetch_dart_arm64_sha256(
                "3.13.5",
                opener=lambda _url, timeout=30: _Resp(),
            )


class TestGetRepoRoot:
    def test_get_repo_root_points_at_workspace(self) -> None:
        root = get_repo_root()
        assert (root / "scripts" / "flutter_sdk_pins.py").is_file()


class TestSyncDockerfilePins:
    def test_sync_updates_stale_pins(self, tmp_path: Path) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")

        def fake_flutter(
            version: str, **_kwargs: object
        ) -> FlutterReleasePins:
            assert version == "3.47.7"
            return FlutterReleasePins(
                flutter_sha256_amd64="c" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="",
                archive_path="stable/linux/flutter_linux_3.47.7-stable.tar.xz",
            )

        def fake_dart(version: str, **_kwargs: object) -> str:
            assert version == "3.13.5"
            return "d" * 64

        changed = sync_dockerfile_pins(
            tmp_path,
            fetch_flutter=fake_flutter,
            fetch_dart_arm64=fake_dart,
        )
        assert changed is True
        text = dockerfile.read_text(encoding="utf-8")
        assert f"ARG FLUTTER_SHA256_AMD64={'c' * 64}" in text
        assert "ARG DART_SDK_VERSION=3.13.5" in text
        assert f"ARG DART_SHA256_ARM64={'d' * 64}" in text

    def test_sync_noop_when_already_current(self, tmp_path: Path) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        current = replace_sdk_pin_args(
            _DOCKERFILE_FIXTURE,
            FlutterReleasePins(
                flutter_sha256_amd64="c" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="d" * 64,
            ),
        )
        dockerfile.write_text(current, encoding="utf-8")

        changed = sync_dockerfile_pins(
            tmp_path,
            fetch_flutter=lambda *_a, **_k: FlutterReleasePins(
                flutter_sha256_amd64="c" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="",
            ),
            fetch_dart_arm64=lambda *_a, **_k: "d" * 64,
        )
        assert changed is False

    def test_sync_missing_dockerfile_raises(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit, match="Dockerfile not found"):
            sync_dockerfile_pins(
                tmp_path,
                fetch_flutter=lambda *_a, **_k: FlutterReleasePins(
                    flutter_sha256_amd64="c" * 64,
                    dart_sdk_version="3.13.5",
                    dart_sha256_arm64="",
                ),
                fetch_dart_arm64=lambda *_a, **_k: "d" * 64,
            )


class TestMain:
    def test_main_check_detects_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")
        monkeypatch.setattr(
            flutter_sdk_pins, "get_repo_root", lambda: tmp_path
        )
        monkeypatch.setattr(
            flutter_sdk_pins,
            "fetch_flutter_linux_pins",
            lambda *_a, **_k: FlutterReleasePins(
                flutter_sha256_amd64="c" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="",
            ),
        )
        monkeypatch.setattr(
            flutter_sdk_pins,
            "fetch_dart_arm64_sha256",
            lambda *_a, **_k: "d" * 64,
        )
        monkeypatch.setattr(sys, "argv", ["flutter_sdk_pins.py", "--check"])
        assert main() == 1

    def test_main_writes_updated_pins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dockerfile = tmp_path / DOCKERFILE_REL
        dockerfile.parent.mkdir(parents=True)
        dockerfile.write_text(_DOCKERFILE_FIXTURE, encoding="utf-8")
        monkeypatch.setattr(
            flutter_sdk_pins, "get_repo_root", lambda: tmp_path
        )
        monkeypatch.setattr(
            flutter_sdk_pins,
            "fetch_flutter_linux_pins",
            lambda *_a, **_k: FlutterReleasePins(
                flutter_sha256_amd64="c" * 64,
                dart_sdk_version="3.13.5",
                dart_sha256_arm64="",
            ),
        )
        monkeypatch.setattr(
            flutter_sdk_pins,
            "fetch_dart_arm64_sha256",
            lambda *_a, **_k: "d" * 64,
        )
        monkeypatch.setattr(sys, "argv", ["flutter_sdk_pins.py"])
        assert main() == 0
        text = dockerfile.read_text(encoding="utf-8")
        assert f"ARG FLUTTER_SHA256_AMD64={'c' * 64}" in text
        assert "ARG DART_SDK_VERSION=3.13.5" in text


class TestCommittedDockerfile:
    def test_committed_dockerfile_pins_match_upstream(self) -> None:
        """Live check: committed pins must match Flutter / Dart archives."""
        assert sync_dockerfile_pins(_ROOT, check=True) is False


class TestModuleMain:
    def test_runpy_path_main_exits_zero_when_current(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cover ``__main__`` via run_path (avoids run_module RuntimeWarning)."""
        dockerfile = (_ROOT / ".cursor" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        flutter_sha = re.search(
            r"^ARG FLUTTER_SHA256_AMD64=([0-9a-f]{64})\s*$",
            dockerfile,
            re.MULTILINE,
        )
        dart_ver = re.search(
            r"^ARG DART_SDK_VERSION=(\d+\.\d+\.\d+)\s*$",
            dockerfile,
            re.MULTILINE,
        )
        dart_sha = re.search(
            r"^ARG DART_SHA256_ARM64=([0-9a-f]{64})\s*$",
            dockerfile,
            re.MULTILINE,
        )
        flutter_ver = re.search(
            r"^ARG FLUTTER_VERSION=(\d+\.\d+\.\d+)\s*$",
            dockerfile,
            re.MULTILINE,
        )
        assert flutter_sha is not None
        assert dart_ver is not None
        assert dart_sha is not None
        assert flutter_ver is not None

        class _Resp:
            def __init__(self, body: str) -> None:
                self._body = body.encode("utf-8")

            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return self._body

        def fake_urlopen(url: object, timeout: float = 30) -> _Resp:
            del timeout
            url_s = str(url)
            if "releases_linux.json" in url_s:
                payload = {
                    "releases": [
                        {
                            "channel": "stable",
                            "version": flutter_ver.group(1),
                            "dart_sdk_version": dart_ver.group(1),
                            "archive": (
                                f"stable/linux/flutter_linux_"
                                f"{flutter_ver.group(1)}-stable.tar.xz"
                            ),
                            "sha256": flutter_sha.group(1),
                        }
                    ]
                }
                return _Resp(json.dumps(payload))
            if "dartsdk-linux-arm64" in url_s:
                return _Resp(f"{dart_sha.group(1)}\n")
            raise AssertionError(f"unexpected URL: {url_s}")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        monkeypatch.setattr(sys, "argv", ["flutter_sdk_pins.py"])
        script = _ROOT / "scripts" / "flutter_sdk_pins.py"
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(str(script), run_name="__main__")
        assert excinfo.value.code == 0
