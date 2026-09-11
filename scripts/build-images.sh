#!/usr/bin/env bash
# build-images.sh — Tier 1 supply-chain build pipeline.
#
# For each in-cluster glue image (fc-signer, fc-rollout-watcher,
# fc-receiver, fc-git-promote-bot):
#   1. docker build with reproducible tag :${VERSION}.
#   2. Capture the local content digest.
#   3. (optional) syft → produce CycloneDX SBOM under sbom/.
#   4. (optional) cosign sign image (keyless OIDC by default).
#   5. (optional) docker push to ${REGISTRY}; capture the registry digest.
#   6. Emit a JSON manifest listing each image + digest + sbom path,
#      consumed by smoke-images-digest-pinned to verify reality matches
#      the manifests/ deployment refs.
#
# Required env:
#   VERSION       image tag to build (default: 1.0.0)
#
# Optional env:
#   REGISTRY      e.g. ghcr.io/fixcontrol — when set, images are pushed
#                 and the registry digest replaces the local digest in
#                 the output manifest.
#   COSIGN_BIN    path to cosign (default: cosign on PATH; skipped if absent)
#   SYFT_BIN      path to syft (default: syft on PATH; skipped if absent)
#   SKIP_PUSH=1   build locally only (kind dev rig)
#   SKIP_SIGN=1   skip cosign even if available
#
# Install pointers:
#   cosign: https://docs.sigstore.dev/cosign/system_config/installation/
#     (Debian-pinned: download v2.4.x release binary, verify SHA, install)
#   syft:   https://github.com/anchore/syft#installation
#
# Output:
#   build/image-manifest.json — for downstream verification + deploy.

set -euo pipefail

VERSION="${VERSION:-1.0.0}"
REGISTRY="${REGISTRY:-}"
# KIND_CLUSTER=<name> side-loads each image into a kind cluster and reads the
# manifest digest back out of the node's containerd, so a dev rig can pin a
# REAL `name@sha256:` reference without a registry. See the block at the end.
KIND_CLUSTER="${KIND_CLUSTER:-}"
COSIGN_BIN="${COSIGN_BIN:-cosign}"
SYFT_BIN="${SYFT_BIN:-syft}"
SKIP_PUSH="${SKIP_PUSH:-0}"
SKIP_SIGN="${SKIP_SIGN:-0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/build"
SBOM_DIR="$ROOT/sbom"
mkdir -p "$BUILD_DIR" "$SBOM_DIR"

# (image-name, dockerfile-path) — names must match repo conventions.
#
# ONLY= restricts the build to a subset, comma-separated. The customer-facing
# install package is fc-agent + fc-test-runner, so that pair is the common case:
#   ONLY=fc-agent,fc-test-runner REGISTRY=… ./scripts/build-images.sh
IMAGES=(
  "fc-signer:docker/signer/Dockerfile"
  "fc-rollout-watcher:docker/watcher/Dockerfile"
  "fc-receiver:docker/receiver/Dockerfile"
  "fc-git-promote-bot:docker/git-promote-bot/Dockerfile"
  "fc-agent:docker/agent/Dockerfile"
  "fc-test-runner:docker/test-runner/Dockerfile"
)

ONLY="${ONLY:-}"
if [[ -n "$ONLY" ]]; then
  filtered=()
  for entry in "${IMAGES[@]}"; do
    case ",$ONLY," in *",${entry%%:*},"*) filtered+=("$entry") ;; esac
  done
  [[ ${#filtered[@]} -gt 0 ]] || { echo "ONLY=$ONLY matched no image" >&2; exit 2; }
  IMAGES=("${filtered[@]}")
fi

# The published package repository carries the two customer-facing images and
# not the rig's four, so an entry whose Dockerfile is absent is a normal state
# there rather than a broken checkout. Skip it and say so — the alternative is
# a customer rebuilding from source and hitting `docker build` on a path that
# was never in their tarball. Every skip is printed, and a tree with no image
# at all still fails rather than producing an empty manifest.
present=()
for entry in "${IMAGES[@]}"; do
  if [[ -f "${entry#*:}" ]]; then
    present+=("$entry")
  else
    echo "[skip] ${entry%%:*} — ${entry#*:} is not in this tree"
  fi
done
[[ ${#present[@]} -gt 0 ]] || { echo "no image Dockerfile found in this tree" >&2; exit 2; }
IMAGES=("${present[@]}")

have() { command -v "$1" >/dev/null 2>&1; }

HAVE_SYFT=0
HAVE_COSIGN=0
if have "$SYFT_BIN";   then HAVE_SYFT=1;   fi
if have "$COSIGN_BIN"; then HAVE_COSIGN=1; fi

if [[ "$HAVE_SYFT" -eq 0 ]]; then
  echo "[warn] syft not found — SBOMs will be skipped. Install: https://github.com/anchore/syft" >&2
fi
if [[ "$HAVE_COSIGN" -eq 0 || "$SKIP_SIGN" = "1" ]]; then
  echo "[warn] cosign skipped (HAVE_COSIGN=$HAVE_COSIGN SKIP_SIGN=$SKIP_SIGN). Install: https://docs.sigstore.dev/cosign" >&2
fi

MANIFEST="$BUILD_DIR/image-manifest.json"
echo "{" > "$MANIFEST"
echo "  \"version\": \"$VERSION\"," >> "$MANIFEST"
echo "  \"registry\": \"${REGISTRY:-}\"," >> "$MANIFEST"
echo "  \"images\": {" >> "$MANIFEST"

n="${#IMAGES[@]}"
for ((i=0; i<n; i++)); do
  entry="${IMAGES[$i]}"
  name="${entry%%:*}"
  dockerfile="${entry#*:}"
  tag="${name}:${VERSION}"

  echo "==> build $tag ($dockerfile)"
  DOCKER_BUILDKIT=0 docker build -t "$tag" -f "$dockerfile" .

  local_digest="$(docker inspect --format '{{.Id}}' "$tag")"
  registry_ref=""
  registry_digest=""
  kind_ref=""
  sbom_path=""
  signed="false"

  # kind side-load. `docker inspect .Id` is the CONFIG digest and is not a
  # reference anything can pull; the node's containerd records the MANIFEST
  # digest of the imported archive, and that one resolves locally as
  # `docker.io/library/<name>@sha256:…` under imagePullPolicy: IfNotPresent.
  # This is what lets a kind rig prove digest pinning for real instead of
  # falling back to a tag.
  if [[ -n "$KIND_CLUSTER" ]]; then
    echo "==> kind load $tag → $KIND_CLUSTER"
    kind load docker-image "$tag" --name "$KIND_CLUSTER" >/dev/null
    node="${KIND_CLUSTER}-control-plane"
    # No `exit` in the awk body and no `head`: closing the pipe early SIGPIPEs
    # `ctr`, and under `set -o pipefail` that fails the whole build for a read
    # that succeeded.
    md="$(docker exec "$node" ctr -n k8s.io images ls 2>/dev/null \
          | awk -v r="docker.io/library/${tag}" '$1==r && !seen {print $3; seen=1}')"
    if [[ -n "$md" ]]; then
      kind_ref="docker.io/library/${name}@${md}"
      # DEV-RIG FIXTURE, and it deserves the label. `kind load` registers the
      # image in containerd under its TAG only, so a Pod asking for
      # `name@sha256:…` gets an ImagePullBackOff even though the exact bytes are
      # sitting on the node: CRI resolves an image by NAME, and the digest form
      # is a different name. Registering the same content under the digest name
      # makes the reference resolvable locally, which is what a registry does
      # for free. Nothing about this changes what the manifests say — the
      # deployed reference is a real digest either way — so the rig proves the
      # production pinning path rather than simulating it.
      docker exec "$node" ctr -n k8s.io images tag "docker.io/library/${tag}" "$kind_ref" >/dev/null 2>&1 || true
      echo "    kind digest: $kind_ref"
    else
      echo "[warn] could not read a manifest digest for $tag from $node" >&2
    fi
  fi

  if [[ -n "$REGISTRY" && "$SKIP_PUSH" != "1" ]]; then
    remote="${REGISTRY}/${name}:${VERSION}"
    echo "==> push $remote"
    docker tag "$tag" "$remote"
    docker push "$remote"
    registry_digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$remote" 2>/dev/null || true)"
    if [[ -n "$registry_digest" ]]; then
      registry_ref="$registry_digest"
    else
      registry_ref="$remote"
    fi
  fi

  if [[ "$HAVE_SYFT" -eq 1 ]]; then
    sbom_path="sbom/${name}-${VERSION}.cdx.json"
    echo "==> syft → $sbom_path"
    "$SYFT_BIN" "$tag" -o cyclonedx-json="$ROOT/$sbom_path"
  fi

  if [[ "$HAVE_COSIGN" -eq 1 && "$SKIP_SIGN" != "1" && -n "$registry_digest" ]]; then
    echo "==> cosign sign $registry_digest"
    "$COSIGN_BIN" sign --yes "$registry_digest"
    if [[ -n "$sbom_path" ]]; then
      "$COSIGN_BIN" attest --yes \
        --predicate "$ROOT/$sbom_path" \
        --type cyclonedx \
        "$registry_digest"
    fi
    signed="true"
  fi

  sep=","
  if [[ $i -eq $((n-1)) ]]; then sep=""; fi
  cat >> "$MANIFEST" <<EOF
    "$name": {
      "tag": "$tag",
      "local_digest": "$local_digest",
      "registry_ref": "$registry_ref",
      "kind_ref": "$kind_ref",
      "sbom": "$sbom_path",
      "signed": $signed
    }$sep
EOF
done

echo "  }" >> "$MANIFEST"
echo "}" >> "$MANIFEST"

echo
echo "wrote $MANIFEST"
cat "$MANIFEST"

# ── build/image-pins.env — the two lines install/values.env needs ──────────
# This is the whole "update the pinned images" flow: build, then paste (or
# source) these two lines. Preference order per image: the registry digest, the
# kind manifest digest, then the tag — so the strongest available reference is
# always the one offered, and install.sh refuses the tag unless
# FC_ALLOW_TAG_IMAGES=1.
PINS="$BUILD_DIR/image-pins.env"
python3 - "$MANIFEST" > "$PINS" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
want = {"fc-agent": "FC_AGENT_IMAGE", "fc-test-runner": "FC_TEST_RUNNER_IMAGE"}
print("# Generated by scripts/build-images.sh — paste into install/values.env.")
print(f"# version={m.get('version')} registry={m.get('registry') or '(none)'}")
for name, var in want.items():
    e = (m.get("images") or {}).get(name)
    if not e:
        continue
    ref = e.get("registry_ref") or e.get("kind_ref") or e.get("tag")
    kind = ("registry digest" if e.get("registry_ref") and "@sha256:" in e["registry_ref"]
            else "kind manifest digest" if e.get("kind_ref")
            else "TAG — install.sh refuses this unless FC_ALLOW_TAG_IMAGES=1")
    print(f"# {name}: {kind}")
    print(f"{var}={ref}")
PY
echo
echo "wrote $PINS"
cat "$PINS"
