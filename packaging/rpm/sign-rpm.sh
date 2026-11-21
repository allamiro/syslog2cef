#!/usr/bin/env bash
# Sign the RPMs in ./rpms with rpmsign, then verify the signatures.
#
# Used by the release (with the release key) and by CI (with a throwaway
# key), so a change in rpm's signing interface fails a pull request
# instead of a release. Expects GPG_PASSPHRASE in the environment and the
# secret key in the gpg keyring; GPG_PRIVATE_KEY, if set, is imported
# first. rpm's own signing command is kept and only the options gpg needs
# to sign unattended are added (%_gpg_sign_cmd_extra_args): overriding
# %__gpg_sign_cmd breaks across rpm versions (rpm 6 runs it differently).
set -euo pipefail

if [ -n "${GPG_PRIVATE_KEY:-}" ]; then
    echo "$GPG_PRIVATE_KEY" | gpg --batch --import
fi
gpg_name="$(gpg --list-secret-keys --with-colons | awk -F: '/^uid/ {print $10; exit}')"

passfile="$(mktemp)"
trap 'rm -f "$passfile"' EXIT
chmod 600 "$passfile"
printf '%s' "$GPG_PASSPHRASE" > "$passfile"

cat >> "$HOME/.rpmmacros" <<MACROS
%_signature gpg
%_gpg_name ${gpg_name}
%_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file ${passfile}
MACROS

rpmsign --addsign rpms/*.rpm

# Verify against the signing key, so an unsigned or wrongly signed package
# fails here rather than on a user's machine.
pubkey="$(mktemp)"
gpg --batch --export --armor "$gpg_name" > "$pubkey"
rpm --import "$pubkey"
rm -f "$pubkey"
rpm --checksig rpms/*.rpm
