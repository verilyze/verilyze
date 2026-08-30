#!/usr/bin/env bash
#
# Per-boot SSH commit-signing setup for verilyze Cloud Agents.
#
# Runs from `start`, so it executes on every boot when the runtime secrets are
# injected. It activates only when the personal `ssh_key` secret is present, so
# agents without it (other contributors, CI, environment builds) are untouched.
#
# It reads the owner's private signing key from the `ssh_key` secret and its
# passphrase from `ssh_key_pass`, materializes a 0600 key under ~/.ssh, and
# configures git to SSH-sign commits and verify them via an allowed_signers
# file (so `make check-signatures` reports a good signature).
#
# The on-disk key lives only on the ephemeral VM and is re-provisioned from the
# secret on each boot. Do not snapshot the VM after this runs, and never commit
# key material -- only the secret NAMES are referenced here, never the values.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "${ssh_key:-}" ]; then
  echo "[sign-setup] ssh_key secret not present; skipping SSH signing setup."
  exit 0
fi

# Attribute commits to the owner. Identity comes from the git_signing_name /
# git_signing_email secrets, not this shared script -- name and email are public
# (they appear in every commit), so secrets here are just the per-user runtime
# channel, and no personal identity is hardcoded in the repository.
if [ -n "${git_signing_name:-}" ]; then
  git config --global user.name "${git_signing_name}"
fi
if [ -n "${git_signing_email:-}" ]; then
  git config --global user.email "${git_signing_email}"
fi

# The allowed_signers principal and commit attribution follow the configured
# committer email. Warn if it is unset or still the Cloud Agent default, since
# that would break attribution and signature verification.
SIGNING_EMAIL="$(git config --global user.email 2>/dev/null || true)"
if [ -z "${SIGNING_EMAIL}" ] || [ "${SIGNING_EMAIL}" = "cursoragent@cursor.com" ]; then
  echo "[sign-setup] WARNING: git_signing_email secret not set; commits would use '${SIGNING_EMAIL:-<unset>}'." >&2
  echo "[sign-setup] Add git_signing_name and git_signing_email secrets for correct attribution and verification." >&2
fi

SSH_DIR="${HOME}/.ssh"
KEY_PATH="${SSH_DIR}/verilyze_signing_ed25519"
PUB_PATH="${KEY_PATH}.pub"
SIGNERS_FILE="${SSH_DIR}/allowed_signers"

umask 077
mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"

# Lock the file's permissions before any secret content lands in it, so the
# private key is never briefly world-/group-readable.
touch "${KEY_PATH}"
chmod 0600 "${KEY_PATH}"

# Materialize the private key with exactly one trailing newline (OpenSSH is
# strict about key framing).
printf '%s\n' "${ssh_key%$'\n'}" >"${KEY_PATH}"

# Strip the passphrase on this ephemeral copy so signing is non-interactive
# across the agent's separate shells (no ssh-agent/socket to propagate).
ssh-keygen -p -P "${ssh_key_pass:-}" -N "" -f "${KEY_PATH}" >/dev/null

# Derive the public key from the private key so it always matches.
ssh-keygen -y -f "${KEY_PATH}" >"${PUB_PATH}"
chmod 644 "${PUB_PATH}"

# allowed_signers maps the committer identity to the key for local
# verification (git %G? -> G). Principal must match the committer email.
printf '%s namespaces="git" %s\n' \
  "${SIGNING_EMAIL}" "$(cat "${PUB_PATH}")" >"${SIGNERS_FILE}"

# Configure git for SSH signing with the owner's key, using the system
# ssh-keygen signer (not the Cursor-managed program).
git config --global gpg.format ssh
git config --global user.signingkey "${KEY_PATH}"
git config --global gpg.ssh.program "$(command -v ssh-keygen)"
git config --global gpg.ssh.allowedSignersFile "${SIGNERS_FILE}"
git config --global commit.gpgsign true

# Belt and suspenders: keep Cursor's managed hook from stamping a
# Co-authored-by trailer on the owner's commits. The managed hooks directory
# is regenerated on each boot, so this is re-applied from `start` every time.
#   - Belt: drop the exec bit on the co-author hook; the dispatcher only runs
#     `commit-msg.cursor*` entries that are executable.
#   - Suspenders: install a strip step whose name sorts after the co-author
#     hook, so if a regenerated hook still runs it, the trailer is removed
#     before the commit object is created and signed.
for coauthor in "${HOME}"/.cursor/agent-hooks/*/commit-msg.cursor.co-author; do
  [ -e "${coauthor}" ] || continue
  chmod -x "${coauthor}" || true
  install -m 0755 "${REPO_ROOT}/.cursor/git-hooks/strip-coauthor.sh" \
    "$(dirname "${coauthor}")/commit-msg.cursor.zz-strip-coauthor"
done

echo "[sign-setup] SSH commit signing configured for ${SIGNING_EMAIL}."
