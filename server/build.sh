#!/bin/bash
# Build the Handover rendezvous/relay servers (hbbs, hbbr) from a pinned upstream commit.
#
# usage: server/build.sh [output dir]
#
# The servers are the open-source rustdesk-server (AGPL-3.0). Two small patches remove the only
# outbound connection they make (a daily update check to the vendor, hbbs only). Everything else
# is upstream at the commit below, built with the committed Cargo.lock (--locked).
set -euo pipefail

REPO=https://github.com/rustdesk/rustdesk-server
COMMIT=a7736be5e40f85bfc141120dce587e836e5d4b80
HBB_COMMON=69cea8dafee147848ae88702029f4bf7df7224c3
TOOLCHAIN=${TOOLCHAIN:-1.99.0}   # any recent stable works; recorded so builds can be repeated

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/build}
SRC=$OUT/src

mkdir -p "$OUT"
[ -d "$SRC/.git" ] || git clone "$REPO" "$SRC"
git -C "$SRC" fetch --quiet origin
git -C "$SRC" reset --quiet --hard
git -C "$SRC" checkout --quiet --detach "$COMMIT"
git -C "$SRC" reset --quiet --hard "$COMMIT"
git -C "$SRC" submodule update --quiet --init --recursive
# start from pristine trees: a previous run leaves the submodule patched, and the patches below must apply cleanly
git -C "$SRC" submodule foreach --quiet --recursive "git reset --quiet --hard && git clean -qfd"
git -C "$SRC" clean -qfd -e target

actual=$(git -C "$SRC/libs/hbb_common" rev-parse HEAD)
if [ "$actual" != "$HBB_COMMON" ]; then
  echo "unexpected hbb_common commit $actual (wanted $HBB_COMMON)" >&2
  exit 1
fi

git -C "$SRC" apply "$HERE/patches/0001-hardening.patch"
git -C "$SRC/libs/hbb_common" apply "$HERE/patches/0002-hbb_common-no-version-check.patch"
git -C "$SRC" apply "$HERE/patches/0003-bump-rustls.patch"
# Handover admission: the shared credential crate (copied, not patched) and the patches that make hbbs/hbbr serve
# only clients holding a credential signed by the owner's issuer (HANDOVER_CA_PUB must be set to start them).
rm -rf "$SRC/libs/handover_cred"
mkdir -p "$SRC/libs/handover_cred"
cp -r "$HERE/../libs/handover_cred/Cargo.toml" "$HERE/../libs/handover_cred/src" "$SRC/libs/handover_cred/"
rm -rf "$SRC/libs/handover_cred/src/bin"
git -C "$SRC" apply "$HERE/patches/0004-handover-admission.patch"
git -C "$SRC/libs/hbb_common" apply "$HERE/patches/0005-hbb_common-admission-fields.patch"

(cd "$SRC" && cargo +"$TOOLCHAIN" build --release --locked)

mkdir -p "$OUT/bin"
cp "$SRC/target/release/hbbs" "$SRC/target/release/hbbr" "$OUT/bin/"
(cd "$OUT/bin" && sha256sum hbbs hbbr | tee SHA256SUMS)
echo "built $COMMIT (hbb_common $HBB_COMMON) with rustc $TOOLCHAIN into $OUT/bin"
