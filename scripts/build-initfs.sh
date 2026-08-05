#!/bin/bash
# Copyright © 2026 Apple Inc. and the Containerization project authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds the guest init filesystem (initfs.ext4) — and optionally a rootfs
# tar.gz for OCI image creation — from the compiled vminitd/vmexec binaries.
#
# Runs INSIDE the Linux dev container (invoked by the root Makefile's `init`
# target via linux_run on macOS, or directly on Linux). A real loop mount is
# preferred; when loop devices aren't available (an unprivileged CI container,
# or a dev VM without loop support) it falls back to `mke2fs -d`, which
# populates the filesystem without mounting. Both paths yield an equivalent
# ext4, so the build works whether or not the container is privileged.
#
# The rootfs layout below MUST stay in sync with cctl's InitImage rootfs
# (Sources/cctl/RootfsCommand.swift): directories bin/ sbin/ dev/ sys/
# proc/self/ run/ tmp/ mnt/ var/, sbin/vminitd + sbin/vmexec at mode 0755, and
# a proc/self/exe -> sbin/vminitd symlink ("hack for swift init's booting").

set -euo pipefail

usage() {
    echo "usage: $0 --vminitd PATH --vmexec PATH --ext4 OUT.ext4 [--tar OUT.tar.gz] [--size 512M] [--add-file SRC:DEST ...]" >&2
    exit 2
}

VMINITD=
VMEXEC=
EXT4=
TAR=
SIZE=512M
# ARCA PATCH: extra files to stage into the guest rootfs, given as SRC:DEST pairs.
# cctl accepted --add-file when it assembled the rootfs itself; the 2026-08 upstream merge
# moved assembly into this script and made `cctl rootfs create` consume a prebuilt tar.
# Staging here rather than post-processing the tar is what also gets the file into the ext4
# initfs, since both outputs are produced from $STAGING below.
ADD_FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --vminitd)  VMINITD=$2; shift 2 ;;
        --vmexec)   VMEXEC=$2;  shift 2 ;;
        --ext4)     EXT4=$2;    shift 2 ;;
        --tar)      TAR=$2;     shift 2 ;;
        --size)     SIZE=$2;    shift 2 ;;
        --add-file) ADD_FILES+=("$2"); shift 2 ;;
        *)          usage ;;
    esac
done

[ -n "$VMINITD" ] && [ -n "$VMEXEC" ] && [ -n "$EXT4" ] || usage
[ -f "$VMINITD" ] || { echo "ERROR: vminitd not found: $VMINITD" >&2; exit 1; }
[ -f "$VMEXEC" ]  || { echo "ERROR: vmexec not found: $VMEXEC"   >&2; exit 1; }

umask 022
STAGING=$(mktemp -d)
MNT=
cleanup() {
    if [ -n "$MNT" ]; then
        mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" 2>/dev/null || true
        rmdir "$MNT" 2>/dev/null || true
    fi
    rm -rf "$STAGING"
}
trap cleanup EXIT

# Directory structure — keep in sync with RootfsCommand.directories.
for d in bin sbin dev sys proc/self run tmp mnt var; do
    mkdir -p "$STAGING/$d"
done
install -m 0755 "$VMINITD" "$STAGING/sbin/vminitd"
install -m 0755 "$VMEXEC" "$STAGING/sbin/vmexec"
ln -sf sbin/vminitd "$STAGING/proc/self/exe"

# ARCA PATCH: stage any --add-file SRC:DEST pairs (e.g. arca-services -> /sbin/arca-services).
for pair in ${ADD_FILES+"${ADD_FILES[@]}"}; do
    src=${pair%%:*}
    dest=${pair#*:}
    if [ "$src" = "$pair" ] || [ -z "$dest" ]; then
        echo "ERROR: --add-file expects SRC:DEST, got: $pair" >&2
        exit 1
    fi
    [ -f "$src" ] || { echo "ERROR: --add-file source not found: $src" >&2; exit 1; }
    mkdir -p "$STAGING/$(dirname "${dest#/}")"
    install -m 0755 "$src" "$STAGING/${dest#/}"
    echo "==> staged $src -> $dest"
done

mkdir -p "$(dirname "$EXT4")"
rm -f "$EXT4"
truncate -s "$SIZE" "$EXT4"

# Prefer a real loop mount; fall back to `mke2fs -d` when it isn't available.
if mkfs.ext4 -F -q "$EXT4" \
    && MNT=$(mktemp -d) \
    && mount -o loop "$EXT4" "$MNT" 2>/dev/null; then
    echo "==> populating $EXT4 via loop mount"
    cp -a "$STAGING"/. "$MNT"/
    sync
    umount "$MNT"
    rmdir "$MNT"
    MNT=
else
    echo "==> loop mount unavailable; populating $EXT4 via mke2fs -d"
    if [ -n "$MNT" ]; then rmdir "$MNT" 2>/dev/null || true; MNT=; fi
    rm -f "$EXT4"
    truncate -s "$SIZE" "$EXT4"
    mkfs.ext4 -F -q -d "$STAGING" "$EXT4"
fi
echo "==> wrote initfs $EXT4"

if [ -n "$TAR" ]; then
    mkdir -p "$(dirname "$TAR")"
    rm -f "$TAR"
    tar -czf "$TAR" -C "$STAGING" .
    echo "==> wrote rootfs tar $TAR"
fi
