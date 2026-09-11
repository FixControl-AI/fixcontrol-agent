#!/usr/bin/env bash
# package-install.sh — the release tarball a customer downloads.
#
# WHAT GOES IN
#   Everything needed to install the agent AND to rebuild its images from
#   source: install/, the two Dockerfiles, the four Python files that are the
#   whole trust boundary, build-images.sh, and the README. An air-gapped
#   platform team that may not pull from ghcr.io can therefore build, push to
#   their own registry, re-pin and install — from this one file.
#
# WHAT STAYS OUT, and why it is checked rather than assumed
#   A real `values.env` holds an agent secret, a repo PAT and a CI token. One
#   in a published tarball is a credential leak with a permanent URL, so the
#   packaging REFUSES rather than filters: a values file that is not the
#   example means this tree was used as a working rig, and the right answer is
#   to notice, not to quietly drop it.
#
# The asset names are a contract with FixControl's enrolment screen, which
# builds the download URLs from the version alone. They are asserted at the
# end of this script for that reason.
#
# Usage:  VERSION=1.0.3 ./scripts/package-install.sh
set -euo pipefail

VERSION="${VERSION:-}"
[[ -n "$VERSION" ]] || { echo "VERSION is required (e.g. VERSION=1.0.3)" >&2; exit 2; }
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "VERSION '$VERSION' is not X.Y.Z" >&2; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/build"
NAME="fixcontrol-agent-${VERSION}"
STAGE="$BUILD_DIR/$NAME"
TARBALL="$BUILD_DIR/${NAME}.tar.gz"

# ── Refuse to package a working rig ────────────────────────────────────────
shopt -s nullglob
leaked=()
for f in install/values*.env; do
  [[ "$(basename "$f")" == "values.example.env" ]] || leaked+=("$f")
done
shopt -u nullglob
if [[ ${#leaked[@]} -gt 0 ]]; then
  echo "ERROR  refusing to package: these hold real values, not the example:" >&2
  printf '       %s\n' "${leaked[@]}" >&2
  echo "       Package from a clean checkout, or move them aside first." >&2
  exit 1
fi

rm -rf "$STAGE" "$TARBALL" "${TARBALL}.sha256"
mkdir -p "$STAGE"

# One copy per path, so a path that disappears from the tree fails the build
# instead of silently shrinking the package a customer depends on.
REQUIRED=(
  install
  docker/agent
  docker/test-runner
  bin/agent.py
  bin/test-runner.py
  bin/fc_agent_common.py
  bin/fc_ed25519.py
  bin/fc-git-askpass
  scripts/build-images.sh
  scripts/package-install.sh
  README.md
)
for path in "${REQUIRED[@]}"; do
  [[ -e "$path" ]] || { echo "ERROR  missing from this tree: $path" >&2; exit 1; }
  mkdir -p "$STAGE/$(dirname "$path")"
  cp -R "$path" "$STAGE/$path"
done
# `[[ … ]] && cp` would be the last command of a failing compound under
# `set -e` when there is no LICENSE, which is a legal state.
if [[ -e LICENSE ]]; then cp LICENSE "$STAGE/LICENSE"; fi

# Generated state that must never travel: a rendered overlay from someone
# else's cluster, and Python bytecode.
rm -rf "$STAGE/install/.render"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE" -name '*.pyc' -delete

# Reproducible-ish: one mtime, sorted entries, no owner/group from this box.
tar --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" \
    --owner=0 --group=0 --numeric-owner \
    -czf "$TARBALL" -C "$BUILD_DIR" "$NAME"

( cd "$BUILD_DIR" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )

# ── The asset-name contract ────────────────────────────────────────────────
# FixControl builds these URLs from the version with no lookup, so a rename
# here is a 404 in a customer's console at the exact moment they are holding a
# shown-once secret.
for expected in "$TARBALL" "${TARBALL}.sha256"; do
  [[ -f "$expected" ]] || { echo "ERROR  expected asset not produced: $expected" >&2; exit 1; }
done

echo "wrote $TARBALL"
cat "${TARBALL}.sha256"
# `| head` closes the pipe early, SIGPIPEs tar, and under `set -o pipefail`
# fails a release for a listing that succeeded. `sed -n` reads to the end.
entries="$(tar -tzf "$TARBALL")"
echo "$entries" | sed -n '1,20p'
echo "…"
echo "$(echo "$entries" | wc -l) entries"
