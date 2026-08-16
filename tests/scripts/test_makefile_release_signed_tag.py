# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Makefile release-tag-push/move must call release-signed-tag.sh."""

from tests.scripts.repo_root import repo_root


def test_release_tag_push_invokes_signed_tag_script() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "release-tag-push:" in text
    assert "release-signed-tag.sh push" in text
    assert "TAG is required" in text


def test_release_tag_move_invokes_signed_tag_script() -> None:
    text = (repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "release-tag-move:" in text
    assert "release-signed-tag.sh move" in text
    assert "TAG is required" in text
