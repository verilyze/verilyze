#!/usr/bin/env bash
#
# Remove any Co-authored-by trailer from the commit message. Installed by
# .cursor/sign-setup.sh into Cursor's managed hooks directory as
# `commit-msg.cursor.zz-strip-coauthor`, whose name sorts after Cursor's
# `commit-msg.cursor.co-author` so the dispatcher runs it afterward. Because
# commit-msg runs before the commit object is created and signed, stripping
# here keeps the trailer out of the commit without breaking the signature.

set -euo pipefail

msg_file="${1:-}"
[ -n "${msg_file}" ] || exit 0

sed -i '/^Co-authored-by:[[:space:]]/d' "${msg_file}"
