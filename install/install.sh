#!/usr/bin/env bash
# install.sh — the FixControl cluster agent, installed from one values file.
#
# WHAT THIS IS
#   A renderer plus `kubectl apply -k`. It reads values.env, writes a complete
#   kustomize overlay into install/.render/, shows you what it will apply, and
#   applies it. Nothing is templated at apply time and nothing is hidden: the
#   render is ordinary YAML you can read, diff, review, or commit to your own
#   GitOps repo (see --render-only).
#
# WHY KUSTOMIZE AND NOT HELM
#   `kubectl` has kustomize built in, so this package adds no tool the platform
#   team does not already have. The customer-varying surface here is small and
#   mostly structural — a namespace, an image digest, a list of egress
#   destinations, a set of ConfigMap keys — which is what overlays are for. A
#   chart would add a templating language, a release-state store and a `helm`
#   dependency to express the same thing, and would make the applied YAML
#   something you infer rather than something you read.
#
# WHY A SCRIPT ON TOP OF KUSTOMIZE
#   Three jobs kustomize cannot do: refuse a bad values file before anything
#   touches the cluster, handle secret material without putting it on a command
#   line, and expand one value (an allowlist of namespaces) into a variable
#   number of resources (one Role + RoleBinding each). Everything else it hands
#   to kustomize.
#
# IDEMPOTENT: re-running with an unchanged values.env applies the same objects
# and changes nothing. ConfigMaps are content-hashed generators, so a changed
# value rolls the pods; an unchanged value does not.
#
# Usage:
#   ./install.sh                     # render + apply + verify
#   ./install.sh --values prod.env   # a different values file
#   ./install.sh --render-only       # write install/.render/ and stop
#   ./install.sh --dry-run           # render + server-side dry-run, no writes
#   ./install.sh --skip-verify       # apply without running verify.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RENDER="$HERE/.render"

VALUES="$HERE/values.env"
RENDER_ONLY=0
DRY_RUN=0
SKIP_VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --values)      VALUES="$2"; shift 2 ;;
    --values=*)    VALUES="${1#*=}"; shift ;;
    --render-only) RENDER_ONLY=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --skip-verify) SKIP_VERIFY=1; shift ;;
    -h|--help)     sed -n '2,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die()  { echo "ERROR  $*" >&2; exit 1; }
warn() { echo "WARN   $*" >&2; }
note() { echo "       $*"; }
step() { echo; echo "==> $*"; }

# ── Load values ────────────────────────────────────────────────────────────
[[ -f "$VALUES" ]] || die "values file not found: $VALUES
       Start from the template:  cp $HERE/values.example.env $HERE/values.env"

# 0600 is not paranoia: this file routinely holds an agent secret, a repo PAT
# and a CI token. A world-readable one is a finding, so say so.
perms="$(stat -c '%a' "$VALUES")"
[[ "$perms" =~ ^[0-7]00$ ]] || warn "$VALUES is mode $perms — it holds secret material; chmod 600 it."

set -a
# shellcheck disable=SC1090
source "$VALUES"
set +a

# Defaults for anything the values file did not set, so an older values.env
# keeps working against a newer package.
: "${FC_URL:=}"; : "${FC_TENANT:=}"; : "${FC_CLUSTER_ID:=}"
: "${FC_AGENT_ID:=}"; : "${FC_AGENT_SECRET:=}"; : "${FC_AGENT_SECRET_FILE:=}"
: "${FC_TEST_RUNNER_AGENT_ID:=}"; : "${FC_TEST_RUNNER_AGENT_SECRET:=}"
: "${FC_TEST_RUNNER_AGENT_SECRET_FILE:=}"
: "${FC_SIGNING_PUBLIC_KEYS:=}"; : "${FC_REQUIRE_SIGNING_PIN:=1}"
: "${FC_AGENT_NAMESPACE:=fixcontrol-agent}"; : "${FC_TEST_RUNNER_NAMESPACE:=fc-test-runner}"
: "${FC_INSTALL_AGENT:=1}"; : "${FC_INSTALL_TEST_RUNNER:=1}"
: "${FC_APPLY_ADMISSION_POLICY:=1}"; : "${FC_APPLY_DEFAULT_DENY:=1}"
: "${FC_AGENT_IMAGE:=}"; : "${FC_TEST_RUNNER_IMAGE:=}"
: "${FC_ALLOW_TAG_IMAGES:=0}"; : "${FC_IMAGE_PULL_SECRET:=}"
: "${FC_ALLOWED_NAMESPACES:=}"; : "${FC_ALLOWED_ROLLOUTS:=*}"; : "${FC_ROLLOUT_NAMESPACES:=}"
: "${FC_AGENT_CAPABILITIES:=rollout.promote,rollout.status}"
: "${FC_PROMOTE_MODE:=git}"; : "${FC_GIT_PROMOTE_REPO:=}"; : "${FC_GIT_PROMOTE_BRANCH:=main}"
: "${FC_GIT_CREDENTIAL:=}"; : "${FC_GIT_CREDENTIAL_FILE:=}"
: "${FC_RECEIVER_URL:=}"; : "${FC_RECEIVER_SECRET:=}"
: "${FC_ARGO_LOCAL_API:=0}"; : "${FC_EVENTS_ENABLED:=1}"
: "${FC_K8S_WEBHOOK_SECRET:=}"; : "${FC_K8S_WEBHOOK_SECRET_FILE:=}"
: "${FC_RECEIVER_SECRET_FILE:=}"
: "${FC_POLL_SECONDS:=10}"
: "${FC_CI_CONFIG_FILE:=}"; : "${FC_GITLAB_TOKEN:=}"; : "${FC_JENKINS_CREDENTIAL:=}"
: "${FC_GITLAB_TOKEN_FILE:=}"; : "${FC_JENKINS_CREDENTIAL_FILE:=}"
: "${FC_CI_CA_FILE:=}"; : "${FC_CI_TIMEOUT_SECONDS:=10}"
: "${FC_EGRESS_FIXCONTROL:=}"; : "${FC_EGRESS_GIT:=}"; : "${FC_EGRESS_CI:=}"
: "${FC_EGRESS_EXTRA:=}"; : "${FC_EGRESS_TEST_RUNNER:=}"; : "${FC_KUBE_APISERVER_CIDR:=}"
: "${FC_ALLOWED_TOOLCHAIN_IMAGE_PREFIXES:=}"; : "${FC_NAMESPACE_TTL_SECONDS:=3600}"
: "${FC_ALLOWED_COMMANDS:=}"
: "${FC_MAX_CONCURRENT_RUNS:=1}"
: "${FC_MANAGE_SECRETS:=1}"
: "${FC_ALLOW_INSECURE_URL:=0}"
: "${FC_ALLOW_INSECURE_TEST_RUNNER_URL:=$FC_ALLOW_INSECURE_URL}"

# merge_env <defaults-file> <overrides-file> <out-file>
# kustomize's configMapGenerator REFUSES a key that appears in two `envs`
# files ("illegally repeats the key"), so the layering is done here instead.
# The result is one readable file per ConfigMap in the render, which is better
# for review anyway: it is the effective configuration, not two halves of it.
# An override with an EMPTY value still wins — "" is how a customer says
# "explicitly nothing" for an allowlist.
merge_env() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
def load(p):
    out = {}
    for line in open(p):
        s = line.strip()
        if not s or s.startswith('#') or '=' not in s:
            continue
        k, _, v = s.partition('=')
        out[k.strip()] = v
    return out
base, over, dest = sys.argv[1], sys.argv[2], sys.argv[3]
merged = load(base)
merged.update(load(over))
with open(dest, 'w') as f:
    f.write("# EFFECTIVE ConfigMap contents. Generated by install/install.sh from\n")
    f.write(f"# {base} (defaults) overlaid with the values file.\n")
    f.write("# Edit values.env and re-run install.sh; do not edit this file.\n")
    for k in sorted(merged):
        f.write(f"{k}={merged[k]}\n")
PY
}

read_val() {  # read_val <inline-value> <file-path> — file wins if set
  local inline="$1" file="$2"
  if [[ -n "$file" ]]; then
    [[ -r "$file" ]] || die "cannot read $file"
    printf '%s' "$(cat "$file")"
  else
    printf '%s' "$inline"
  fi
}

# ── Validate, loudly, before anything touches the cluster ──────────────────
step "Validating $VALUES"

[[ "$FC_INSTALL_AGENT" == "1" || "$FC_INSTALL_TEST_RUNNER" == "1" ]] \
  || die "FC_INSTALL_AGENT and FC_INSTALL_TEST_RUNNER are both 0 — nothing to install."

[[ -n "$FC_URL" ]]        || die "FC_URL is required."
[[ -n "$FC_TENANT" ]]     || die "FC_TENANT is required — check 1 (tenant_mismatch) cannot be enforced without it."
[[ -n "$FC_CLUSTER_ID" ]] || die "FC_CLUSTER_ID is required — check 2 (cluster_mismatch) cannot be enforced without it."

case "$FC_URL" in
  https://*) : ;;
  http://*)
    [[ "$FC_ALLOW_INSECURE_URL" == "1" ]] \
      || die "FC_URL is plaintext http://. Set FC_ALLOW_INSECURE_URL=1 only on a dev rig."
    warn "══ DEV ESCAPE HATCH ══ FC_URL is plaintext http://. The agent secret and every"
    warn "                       operation result travel unencrypted. Never on a real cluster."
    ;;
  *) die "FC_URL must start with http:// or https://" ;;
esac

if [[ -z "$FC_SIGNING_PUBLIC_KEYS" ]]; then
  if [[ "$FC_REQUIRE_SIGNING_PIN" == "1" ]]; then
    die "FC_SIGNING_PUBLIC_KEYS is empty and FC_REQUIRE_SIGNING_PIN=1.
       Without a pin the key that AUTHORIZES this agent is the key the agent HOLDS:
       a compromise of the pod is a compromise of the authority over the pod.
       Get the value from a FixControl operator:
         npx tsx scripts/agent-signing-key.ts export
       Set FC_REQUIRE_SIGNING_PIN=0 only to keep a pre-Step-16 install running."
  fi
  warn "No signing-key pin. Running in LEGACY shared-secret verification — a migration"
  warn "state, not a posture. See README Step 16."
fi

validate_image() {  # validate_image <var-name> <value>
  local var="$1" ref="$2"
  [[ -n "$ref" ]] || die "$var is required."
  case "$ref" in
    *:latest) die "$var is a :latest tag. Never." ;;
    *@sha256:*) return 0 ;;
  esac
  [[ "$FC_ALLOW_TAG_IMAGES" == "1" ]] || die \
    "$var=$ref is a tag, not a digest.
       A tag is a name that can be repointed; this workload holds the tenant's agent
       secret, your manifests-repo PAT and your CI credentials. Pin it:
         VERSION=… REGISTRY=… ./scripts/build-images.sh   → build/image-pins.env
       Set FC_ALLOW_TAG_IMAGES=1 only for a local kind rig with side-loaded images."
  warn "══ DEV ESCAPE HATCH ══ $var is a tag ($ref), not a digest."
}

[[ "$FC_INSTALL_AGENT" == "1" ]] && {
  validate_image FC_AGENT_IMAGE "$FC_AGENT_IMAGE"
  [[ -n "$FC_AGENT_ID" ]] || die "FC_AGENT_ID is required when FC_INSTALL_AGENT=1."
  [[ -n "$FC_ALLOWED_NAMESPACES" ]] || die \
    "FC_ALLOWED_NAMESPACES is empty, which allowlists NOTHING.
       There is deliberately no spelling for 'all namespaces'. Name the namespaces
       whose Rollouts a governed FixControl decision may advance."
  case "$FC_PROMOTE_MODE" in
    git)
      [[ -n "$FC_GIT_PROMOTE_REPO" ]] || die "FC_PROMOTE_MODE=git needs FC_GIT_PROMOTE_REPO." ;;
    receiver)
      [[ -n "$FC_RECEIVER_URL" ]] || die "FC_PROMOTE_MODE=receiver needs FC_RECEIVER_URL." ;;
    none)
      # A CI/CD-gate-only agent has no promotion path at all: it carries
      # approve/reject verdicts to a private GitLab/Jenkins and never touches a
      # Rollout. Before `none` existed such an install had to name a manifests
      # repo it would never clone — a value that reads as a fact and is not
      # one. `none` is refused the moment the agent actually CLAIMS
      # rollout.promote, so it cannot be used to hide a missing repo.
      [[ "$FC_AGENT_CAPABILITIES" != *rollout.promote* ]] || die \
        "FC_PROMOTE_MODE=none but FC_AGENT_CAPABILITIES claims rollout.promote.
       An agent that may promote needs a promotion path. Pick git or receiver,
       or drop rollout.promote from FC_AGENT_CAPABILITIES." ;;
    *) die "FC_PROMOTE_MODE must be 'git', 'receiver' or 'none' (got: $FC_PROMOTE_MODE)." ;;
  esac
  if [[ "$FC_AGENT_CAPABILITIES" == *ci.* && -z "$FC_CI_CONFIG_FILE" ]]; then
    die "A ci.* capability is claimed but FC_CI_CONFIG_FILE is empty.
       Every CI operation would be refused not_allowlisted — safe, but a
       misconfiguration rather than a policy. Point at a CI config, or drop the
       capability from FC_AGENT_CAPABILITIES."
  fi
  if [[ -n "$FC_CI_CONFIG_FILE" ]]; then
    [[ -r "$FC_CI_CONFIG_FILE" ]] || die "FC_CI_CONFIG_FILE not readable: $FC_CI_CONFIG_FILE"
    python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$FC_CI_CONFIG_FILE" \
      || die "FC_CI_CONFIG_FILE is not valid JSON: $FC_CI_CONFIG_FILE"
    [[ -n "$FC_EGRESS_CI" ]] || warn \
      "A CI config is set but FC_EGRESS_CI is empty — the NetworkPolicy will not open a
       path to those hosts and every CI operation will fail host_unreachable."
  fi
  [[ -n "$FC_EGRESS_FIXCONTROL" ]] || die \
    "FC_EGRESS_FIXCONTROL is empty. The agent's NetworkPolicy would then permit no route
       to FixControl at all. Name the destination — an ipBlock for the resolved
       api.fixcontrol.ai address, or the CIDR of your egress proxy."
  if [[ "$FC_PROMOTE_MODE" == "git" && -z "$FC_EGRESS_GIT" ]]; then
    warn "PROMOTE_MODE=git with an empty FC_EGRESS_GIT — promotions will fail
       'git clone failed'. Set it unless the forge shares FC_EGRESS_FIXCONTROL's rule."
  fi
}

[[ "$FC_INSTALL_TEST_RUNNER" == "1" ]] && {
  validate_image FC_TEST_RUNNER_IMAGE "$FC_TEST_RUNNER_IMAGE"
  [[ -n "$FC_TEST_RUNNER_AGENT_ID" ]] || die \
    "FC_TEST_RUNNER_AGENT_ID is required when FC_INSTALL_TEST_RUNNER=1.
       It must be a SEPARATE registration from FC_AGENT_ID — one identity executes
       customer test plans, the other advances production rollouts."
  [[ "$FC_TEST_RUNNER_AGENT_ID" != "$FC_AGENT_ID" ]] || die \
    "FC_TEST_RUNNER_AGENT_ID equals FC_AGENT_ID. The separation is the security
       property; sharing the identity removes it. Register a second agent."
  : "${FC_EGRESS_TEST_RUNNER:=$FC_EGRESS_FIXCONTROL}"
  [[ -n "$FC_EGRESS_TEST_RUNNER" ]] || die \
    "FC_EGRESS_TEST_RUNNER (or FC_EGRESS_FIXCONTROL) is required for the test runner."
}
: "${FC_EGRESS_TEST_RUNNER:=$FC_EGRESS_FIXCONTROL}"

command -v kubectl >/dev/null || die "kubectl not on PATH."
kubectl version --client -o json >/dev/null 2>&1 || die "kubectl is not usable."
kubectl cluster-info >/dev/null 2>&1 || die "no reachable cluster in the current kubectl context."
CONTEXT="$(kubectl config current-context)"
note "kubectl context: $CONTEXT"

# ── Cluster facts the render needs ─────────────────────────────────────────
if [[ -z "$FC_KUBE_APISERVER_CIDR" ]]; then
  api_ip="$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
  [[ -n "$api_ip" ]] || die "could not read the kubernetes Service ClusterIP; set FC_KUBE_APISERVER_CIDR."
  FC_KUBE_APISERVER_CIDR="${api_ip}/32"
fi
note "kube-apiserver egress target: $FC_KUBE_APISERVER_CIDR"

K8S_MINOR="$(kubectl version -o json 2>/dev/null | python3 -c \
  'import json,sys,re; d=json.load(sys.stdin); print(re.sub(r"[^0-9].*","",d["serverVersion"]["minor"]))' 2>/dev/null || echo 0)"
APPLY_VAP="$FC_APPLY_ADMISSION_POLICY"
if [[ "$APPLY_VAP" == "1" && "$FC_INSTALL_TEST_RUNNER" != "1" ]]; then
  APPLY_VAP=0
  note "admission policy skipped: it governs fc-test-runner and the runner is not being installed."
elif [[ "$APPLY_VAP" == "1" && "${K8S_MINOR:-0}" -lt 30 ]]; then
  APPLY_VAP=0
  warn "Kubernetes 1.${K8S_MINOR} predates GA ValidatingAdmissionPolicy (1.30). Skipping it."
  warn "fc-test-runner's namespace scoping then rests on the code alone. Transcribe the"
  warn "expressions in install/base/admission/validatingadmissionpolicy.yaml into your"
  warn "policy engine, or accept the documented caveat in that file's header."
fi

# ── Render ─────────────────────────────────────────────────────────────────
step "Rendering $RENDER"
rm -rf "$RENDER"
mkdir -p "$RENDER"

split_ref() {  # split_ref <ref> → prints "name|digest|tag"
  local ref="$1"
  if [[ "$ref" == *"@sha256:"* ]]; then
    printf '%s|%s|\n' "${ref%@sha256:*}" "sha256:${ref##*@sha256:}"
  else
    printf '%s||%s\n' "${ref%:*}" "${ref##*:}"
  fi
}

image_transformer() {  # image_transformer <base-image-name> <ref>
  local base="$1" parsed name digest tag
  parsed="$(split_ref "$2")"
  name="${parsed%%|*}"; parsed="${parsed#*|}"
  digest="${parsed%%|*}"; tag="${parsed#*|}"
  echo "images:"
  echo "  - name: $base"
  echo "    newName: $name"
  [[ -n "$digest" ]] && echo "    digest: $digest"
  [[ -n "$tag"    ]] && echo "    newTag: $tag"
  return 0
}

# egress_rules <spec> — turn the values grammar into NetworkPolicy egress items.
#   <cidr>:<port>                     → ipBlock
#   <namespace>|<key>=<value>:<port>  → namespaceSelector + podSelector, ONE item
# Consecutive entries with the same destination are NOT merged: one line in
# values.env is one rule in the policy, so the applied object reads back as the
# list the operator wrote.
egress_rules() {
  local spec="$1" entry dest port ns sel key val
  [[ -n "$spec" ]] || return 0
  local IFS=,
  for entry in $spec; do
    entry="$(echo "$entry" | tr -d '[:space:]')"
    [[ -n "$entry" ]] || continue
    port="${entry##*:}"; dest="${entry%:*}"
    [[ "$port" =~ ^[0-9]+$ ]] || die "egress entry '$entry': missing or non-numeric :port"
    if [[ "$dest" == *"|"* ]]; then
      ns="${dest%%|*}"; sel="${dest#*|}"
      key="${sel%%=*}"; val="${sel#*=}"
      [[ -n "$ns" && -n "$key" && -n "$val" ]] || die "egress entry '$entry': expected <namespace>|<key>=<value>:<port>"
      cat <<EOF
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: $ns }
          podSelector:
            matchLabels: { $key: "$val" }
      ports:
        - { protocol: TCP, port: $port }
EOF
    else
      [[ "$dest" == */* ]] || die "egress entry '$entry': a CIDR needs a prefix length, e.g. 203.0.113.10/32:443"
      cat <<EOF
    - to:
        - ipBlock: { cidr: $dest }
      ports:
        - { protocol: TCP, port: $port }
EOF
    fi
  done
}

dns_rule() {
  cat <<'EOF'
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
EOF
}

apiserver_rule() {
  cat <<EOF
    - to:
        - ipBlock: { cidr: $FC_KUBE_APISERVER_CIDR }
      ports:
        - { protocol: TCP, port: 443 }
EOF
}

ROOT_RESOURCES=()

# ── agent ──────────────────────────────────────────────────────────────────
if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  mkdir -p "$RENDER/agent"
  cp "$HERE/base/agent/config-defaults.env" "$RENDER/agent/config-defaults.env"
  if [[ -n "$FC_CI_CONFIG_FILE" ]]; then
    cp "$FC_CI_CONFIG_FILE" "$RENDER/agent/ci-config.json"
  else
    cp "$HERE/base/agent/ci-config-empty.json" "$RENDER/agent/ci-config.json"
  fi

  # The ConfigMap overrides. Only keys the customer actually set; everything
  # else stays at the documented default in config-defaults.env, which is
  # copied next to this file so the render is self-contained.
  {
    echo "# Generated by install.sh from $VALUES — do not edit; edit values.env."
    echo "ALLOWED_NAMESPACES=$FC_ALLOWED_NAMESPACES"
    echo "ALLOWED_ROLLOUTS=$FC_ALLOWED_ROLLOUTS"
    echo "AGENT_CAPABILITIES=$FC_AGENT_CAPABILITIES"
    echo "FIXCONTROL_SIGNING_PUBLIC_KEYS=$FC_SIGNING_PUBLIC_KEYS"
    echo "PROMOTE_MODE=$FC_PROMOTE_MODE"
    echo "GIT_PROMOTE_REPO=$FC_GIT_PROMOTE_REPO"
    echo "GIT_PROMOTE_BRANCH=$FC_GIT_PROMOTE_BRANCH"
    echo "RECEIVER_URL=$FC_RECEIVER_URL"
    echo "ARGO_LOCAL_API=$FC_ARGO_LOCAL_API"
    echo "EVENTS_ENABLED=$FC_EVENTS_ENABLED"
    echo "POLL_SECONDS=$FC_POLL_SECONDS"
    echo "CI_TIMEOUT_SECONDS=$FC_CI_TIMEOUT_SECONDS"
    [[ -n "$FC_CI_CA_FILE" ]] && echo "CI_CA_BUNDLE=/etc/fc-agent/ci-ca/ca.crt"
    [[ "$FC_ALLOW_INSECURE_URL" == "1" ]] && echo "ALLOW_INSECURE_FIXCONTROL_URL=1"
    true
  } > "$RENDER/agent/overrides.env"
  merge_env "$RENDER/agent/config-defaults.env" "$RENDER/agent/overrides.env" "$RENDER/agent/config.env"

  # The egress policy, replaced in full.
  {
    echo "apiVersion: networking.k8s.io/v1"
    echo "kind: NetworkPolicy"
    echo "metadata:"
    echo "  name: fc-agent-egress"
    echo "spec:"
    echo "  egress:"
    dns_rule
    apiserver_rule
    egress_rules "$FC_EGRESS_FIXCONTROL"
    egress_rules "$FC_EGRESS_GIT"
    egress_rules "$FC_EGRESS_CI"
    egress_rules "$FC_EGRESS_EXTRA"
  } > "$RENDER/agent/egress-patch.yaml"

  # Deployment extras that depend on values: a pull secret, the CI CA mount.
  {
    echo "apiVersion: apps/v1"
    echo "kind: Deployment"
    echo "metadata:"
    echo "  name: fc-agent"
    echo "spec:"
    echo "  template:"
    echo "    spec:"
    if [[ -n "$FC_IMAGE_PULL_SECRET" ]]; then
      echo "      imagePullSecrets:"
      echo "        - name: $FC_IMAGE_PULL_SECRET"
    fi
    if [[ -n "$FC_CI_CA_FILE" ]]; then
      echo "      volumes:"
      echo "        - name: work"
      echo "          emptyDir: { sizeLimit: 256Mi }"
      echo "        - name: ci-ca"
      echo "          configMap: { name: fc-agent-ci-ca }"
      echo "      containers:"
      echo "        - name: fc-agent"
      echo "          volumeMounts:"
      echo "            - { name: work, mountPath: /tmp }"
      echo "            - { name: ci-ca, mountPath: /etc/fc-agent/ci-ca, readOnly: true }"
    else
      echo "      containers:"
      echo "        - name: fc-agent"
      echo "          imagePullPolicy: IfNotPresent"
    fi
  } > "$RENDER/agent/deployment-patch.yaml"

  {
    cat <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
# GENERATED by install/install.sh from $VALUES. Readable on purpose: this is
# the complete overlay, and committing it to a GitOps repo is a supported way
# to run this package (\`./install.sh --render-only\`).
namespace: $FC_AGENT_NAMESPACE
resources:
  - ../../base/agent
EOF
    [[ "$FC_APPLY_DEFAULT_DENY" == "1" ]] && echo "  - ../../base/agent-default-deny"
    image_transformer fc-agent "$FC_AGENT_IMAGE"
    cat <<EOF
configMapGenerator:
  - name: fc-agent-config
    envs:
      - config.env
    files:
      - CI_CONFIG=ci-config.json
EOF
    if [[ -n "$FC_CI_CA_FILE" ]]; then
      cat <<EOF
  - name: fc-agent-ci-ca
    files:
      - ca.crt=ci-ca.crt
    options:
      disableNameSuffixHash: true
EOF
      cp "$FC_CI_CA_FILE" "$RENDER/agent/ci-ca.crt"
    fi
    cat <<EOF
patches:
  - path: egress-patch.yaml
    target: { kind: NetworkPolicy, name: fc-agent-egress }
  - path: deployment-patch.yaml
    target: { kind: Deployment, name: fc-agent }
EOF
  } > "$RENDER/agent/kustomization.yaml"
  ROOT_RESOURCES+=("agent")

  # One Role + RoleBinding per rollout namespace.
  rollout_ns_list="${FC_ROLLOUT_NAMESPACES:-$FC_ALLOWED_NAMESPACES}"
  idx=0
  IFS=, read -r -a _rns <<< "$rollout_ns_list"
  for ns in "${_rns[@]}"; do
    ns="$(echo "$ns" | tr -d '[:space:]')"; [[ -n "$ns" ]] || continue
    idx=$((idx+1))
    d="$RENDER/rollout-rbac-$ns"
    mkdir -p "$d"
    cat > "$d/subject-patch.yaml" <<EOF
# The ServiceAccount lives in the agent's namespace; the Role lives where the
# Rollouts are. kustomize's \`namespace:\` transformer would otherwise rewrite
# the subject to this namespace, which would bind nothing.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: fc-rollout-controller
subjects:
  - kind: ServiceAccount
    name: fc-rollout-controller
    namespace: $FC_AGENT_NAMESPACE
EOF
    {
      cat <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: $ns
resources:
  - ../../base/rollout-rbac
patches:
  - path: subject-patch.yaml
    target: { kind: RoleBinding, name: fc-rollout-controller }
EOF
      if [[ "$FC_ARGO_LOCAL_API" == "1" ]]; then
        cat > "$d/local-api-patch.yaml" <<'EOF'
# FC_ARGO_LOCAL_API=1: the abort path issues exactly one write, a PATCH of the
# status subresource. Nothing else is added, and with ARGO_LOCAL_API=0 this
# identity holds NO write verb against argoproj.io anywhere.
- op: add
  path: /rules/-
  value:
    apiGroups: ["argoproj.io"]
    resources: ["rollouts/status"]
    verbs: ["patch"]
EOF
        cat <<EOF
  - path: local-api-patch.yaml
    target: { kind: Role, name: fc-rollout-controller }
EOF
      fi
      if [[ "$FC_EVENTS_ENABLED" != "1" ]]; then
        cat > "$d/no-list-patch.yaml" <<'EOF'
# EVENTS_ENABLED=0: nothing LISTs the rollouts collection any more, so the
# grant that made it possible goes too. `get` alone covers check 7 and
# rollout.status.
- op: replace
  path: /rules/0/verbs
  value: ["get"]
EOF
        cat <<EOF
  - path: no-list-patch.yaml
    target: { kind: Role, name: fc-rollout-controller }
EOF
      fi
    } > "$d/kustomization.yaml"
    ROOT_RESOURCES+=("rollout-rbac-$ns")
  done
  note "rollout RBAC namespaces: ${rollout_ns_list}"
fi

# ── test runner ────────────────────────────────────────────────────────────
if [[ "$FC_INSTALL_TEST_RUNNER" == "1" ]]; then
  mkdir -p "$RENDER/test-runner"
  cp "$HERE/base/test-runner/config-defaults.env" "$RENDER/test-runner/config-defaults.env"
  {
    echo "# Generated by install.sh from $VALUES — do not edit; edit values.env."
    echo "FIXCONTROL_SIGNING_PUBLIC_KEYS=$FC_SIGNING_PUBLIC_KEYS"
    echo "NAMESPACE_TTL_SECONDS=$FC_NAMESPACE_TTL_SECONDS"
    echo "MAX_CONCURRENT_RUNS=$FC_MAX_CONCURRENT_RUNS"
    echo "ALLOWED_TOOLCHAIN_IMAGE_PREFIXES=$FC_ALLOWED_TOOLCHAIN_IMAGE_PREFIXES"
    # Empty is not "allow nothing" here: it means the runner's built-in
    # default command set (FixControl's own closed list). See the reasoning in
    # base/test-runner/config-defaults.env — a customer value REPLACES it.
    echo "ALLOWED_COMMANDS=$FC_ALLOWED_COMMANDS"
    # RUNNER_IMAGE and the container image come from ONE value, so the
    # self-reference the runner uses for its fetch/sentinel containers can
    # never drift from the image that is actually running. verify.sh asserts it.
    echo "RUNNER_IMAGE=$FC_TEST_RUNNER_IMAGE"
    [[ "$FC_ALLOW_INSECURE_TEST_RUNNER_URL" == "1" ]] && echo "ALLOW_INSECURE_FIXCONTROL_URL=1"
    true
  } > "$RENDER/test-runner/overrides.env"
  merge_env "$RENDER/test-runner/config-defaults.env" "$RENDER/test-runner/overrides.env" "$RENDER/test-runner/config.env"

  {
    echo "apiVersion: networking.k8s.io/v1"
    echo "kind: NetworkPolicy"
    echo "metadata:"
    echo "  name: fc-test-runner-egress"
    echo "spec:"
    echo "  egress:"
    dns_rule
    apiserver_rule
    egress_rules "$FC_EGRESS_TEST_RUNNER"
  } > "$RENDER/test-runner/egress-patch.yaml"

  {
    echo "apiVersion: apps/v1"
    echo "kind: Deployment"
    echo "metadata:"
    echo "  name: fc-test-runner"
    echo "spec:"
    echo "  template:"
    echo "    spec:"
    if [[ -n "$FC_IMAGE_PULL_SECRET" ]]; then
      echo "      imagePullSecrets:"
      echo "        - name: $FC_IMAGE_PULL_SECRET"
    fi
    echo "      containers:"
    echo "        - name: test-runner"
    echo "          imagePullPolicy: IfNotPresent"
  } > "$RENDER/test-runner/deployment-patch.yaml"

  {
    cat <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
# GENERATED by install/install.sh from $VALUES.
namespace: $FC_TEST_RUNNER_NAMESPACE
resources:
  - ../../base/test-runner
EOF
    image_transformer fc-test-runner "$FC_TEST_RUNNER_IMAGE"
    cat <<EOF
configMapGenerator:
  - name: fc-test-runner-config
    envs:
      - config.env
patches:
  - path: egress-patch.yaml
    target: { kind: NetworkPolicy, name: fc-test-runner-egress }
  - path: deployment-patch.yaml
    target: { kind: Deployment, name: fc-test-runner }
EOF
  } > "$RENDER/test-runner/kustomization.yaml"
  ROOT_RESOURCES+=("test-runner")
fi

# ── admission policy ───────────────────────────────────────────────────────
if [[ "$APPLY_VAP" == "1" ]]; then
  mkdir -p "$RENDER/admission"
  sa="system:serviceaccount:${FC_TEST_RUNNER_NAMESPACE}:fc-test-runner"
  cat > "$RENDER/admission/identity-patch.yaml" <<EOF
# The policy governs exactly one identity, and names the runner's own namespace
# so it cannot delete the namespace it lives in (which satisfies the fc-test-
# prefix by accident).
- op: replace
  path: /spec/matchConditions/0/expression
  value: "request.userInfo.username == '$sa'"
- op: replace
  path: /spec/variables/0/expression
  value: "'$FC_TEST_RUNNER_NAMESPACE'"
EOF
  cat > "$RENDER/admission/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base/admission
patches:
  - path: identity-patch.yaml
    target: { kind: ValidatingAdmissionPolicy, name: fc-test-runner-namespace-scope }
EOF
  ROOT_RESOURCES+=("admission")
fi

{
  # QUOTED heredoc: this block has no variables to expand, and the comment
  # below contains backticks. An unquoted heredoc would run them as command
  # substitutions — printing "part-of: command not found" on every render and
  # silently deleting the words from the generated file.
  cat <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
# GENERATED by install/install.sh — the complete install, in one apply.
# BOTH labels on every object, generators included. `part-of` is what
# uninstall.sh sweeps on, and a kustomize-generated ConfigMap inherits only
# what this transformer gives it — a hashed `fc-agent-config-…` with no
# `part-of` would survive an uninstall that keeps a customer-owned namespace.
# includeSelectors: false so nothing touches a Deployment's matchLabels.
labels:
  - includeSelectors: false
    pairs:
      app.kubernetes.io/managed-by: fixcontrol-install
      app.kubernetes.io/part-of: fixcontrol-agent
resources:
EOF
  for r in "${ROOT_RESOURCES[@]}"; do echo "  - $r"; done
} > "$RENDER/kustomization.yaml"

kubectl kustomize "$RENDER" > "$RENDER/rendered.yaml" \
  || die "kustomize could not render $RENDER — see the error above."
note "rendered $(grep -c '^kind:' "$RENDER/rendered.yaml") objects → $RENDER/rendered.yaml"

if [[ "$RENDER_ONLY" == "1" ]]; then
  step "Render only — nothing applied"
  note "review:  $RENDER/rendered.yaml"
  note "apply:   kubectl apply -k $RENDER"
  exit 0
fi

# ── Namespaces ─────────────────────────────────────────────────────────────
# The agent's namespace may be one the customer already owns, so it is created
# only when missing and annotated when this installer created it — uninstall.sh
# reads that annotation and refuses to delete a namespace it did not create.
ensure_namespace() {
  local ns="$1"
  if kubectl get ns "$ns" >/dev/null 2>&1; then
    note "namespace $ns exists"
  else
    step "Creating namespace $ns"
    [[ "$DRY_RUN" == "1" ]] && { note "(dry-run)"; return 0; }
    kubectl create ns "$ns"
    kubectl annotate ns "$ns" fixcontrol.ai/created-by=fixcontrol-install --overwrite
    kubectl label ns "$ns" \
      app.kubernetes.io/part-of=fixcontrol-agent \
      pod-security.kubernetes.io/enforce=restricted \
      pod-security.kubernetes.io/enforce-version=latest --overwrite
  fi
}
[[ "$FC_INSTALL_AGENT" == "1" ]] && ensure_namespace "$FC_AGENT_NAMESPACE"
# The runner's namespace is a resource in its own base — kubectl apply creates it.

# ── Nonce ledgers: CREATE IF ABSENT, never apply ───────────────────────────
# These two ConfigMaps are the only objects in the package whose content
# belongs to the running process rather than to the install. `kubectl apply` of
# a declarative `data: {}` would reset them on every re-run, silently erasing
# the single-use replay ledger — the second install.sh run on the kind rig
# printed `configmap/fc-agent-nonces configured` while everything else said
# `unchanged`, which is exactly what that looks like from the outside.
#
# Their names are pinned by `resourceNames` in the Roles, so they carry no
# generator hash and never move. They carry the package labels so uninstall.sh
# removes them and proves it.
ensure_nonce_configmap() {  # ensure_nonce_configmap <ns> <name> <component>
  local ns="$1" name="$2" comp="$3"
  [[ "$DRY_RUN" == "1" ]] && { note "(dry-run) nonce ledger $ns/$name"; return 0; }
  if kubectl -n "$ns" get cm "$name" >/dev/null 2>&1; then
    note "nonce ledger $ns/$name exists — left untouched"
    return 0
  fi
  kubectl -n "$ns" create configmap "$name" >/dev/null
  kubectl -n "$ns" label configmap "$name" \
    "app.kubernetes.io/name=$comp" \
    app.kubernetes.io/part-of=fixcontrol-agent \
    app.kubernetes.io/managed-by=fixcontrol-install >/dev/null
  note "nonce ledger $ns/$name created"
}
[[ "$FC_INSTALL_AGENT" == "1" ]] && \
  ensure_nonce_configmap "$FC_AGENT_NAMESPACE" fc-agent-nonces fc-agent

# ── Secrets ────────────────────────────────────────────────────────────────
# Material never reaches a command line (and therefore never reaches `ps`, a
# shell history file or a process-listing sidecar). Each key is written to a
# 0600 file inside a private temp directory and handed to kubectl with
# --from-file; the directory is removed on every exit path.
SECRET_TMP=""
cleanup() { [[ -n "$SECRET_TMP" && -d "$SECRET_TMP" ]] && rm -rf "$SECRET_TMP"; }
trap cleanup EXIT

apply_secret() {  # apply_secret <namespace> <name> <key=value> ...
  local ns="$1" name="$2"; shift 2
  local args=() kv k v
  SECRET_TMP="$(mktemp -d)"; chmod 700 "$SECRET_TMP"
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    [[ -n "$v" ]] || continue
    printf '%s' "$v" > "$SECRET_TMP/$k"
    chmod 600 "$SECRET_TMP/$k"
    args+=("--from-file=$k=$SECRET_TMP/$k")
  done
  kubectl -n "$ns" create secret generic "$name" "${args[@]}" \
      --dry-run=client -o yaml \
    | kubectl label --local -f - -o yaml \
        app.kubernetes.io/part-of=fixcontrol-agent \
        app.kubernetes.io/managed-by=fixcontrol-install \
    | { [[ "$DRY_RUN" == "1" ]] && kubectl apply --dry-run=server -f - >/dev/null || kubectl apply -f - >/dev/null; }
  rm -rf "$SECRET_TMP"; SECRET_TMP=""
  # Say which of the two just happened. The line used to read "applied" in
  # both modes, which tells an operator running --dry-run that they have just
  # overwritten a live credential — in an installer whose stated contract for
  # that flag is that it writes nothing.
  if [[ "$DRY_RUN" == "1" ]]; then
    note "(dry-run) secret $ns/$name would be applied (${#args[@]} keys)"
  else
    note "secret $ns/$name applied (${#args[@]} keys)"
  fi
}

require_secret_keys() {  # require_secret_keys <ns> <name> <key> ...
  local ns="$1" name="$2"; shift 2
  local present missing=()
  present="$(kubectl -n "$ns" get secret "$name" -o jsonpath='{.data}' 2>/dev/null || true)"
  [[ -n "$present" ]] || die "FC_MANAGE_SECRETS=0 but Secret $ns/$name does not exist.
       Your External Secrets / Vault / Sealed Secrets bundle must create it first."
  for k in "$@"; do
    [[ "$present" == *"\"$k\""* ]] || missing+=("$k")
  done
  [[ ${#missing[@]} -eq 0 ]] || die "Secret $ns/$name is missing key(s): ${missing[*]}"
  note "secret $ns/$name verified (externally managed)"
}

if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  if [[ "$FC_MANAGE_SECRETS" == "1" ]]; then
    step "$([[ "$DRY_RUN" == "1" ]] && echo "Agent credentials (dry-run)" || echo "Applying agent credentials")"
    apply_secret "$FC_AGENT_NAMESPACE" fc-agent \
      "fixcontrol-url=$FC_URL" \
      "agent-id=$FC_AGENT_ID" \
      "agent-secret=$(read_val "$FC_AGENT_SECRET" "$FC_AGENT_SECRET_FILE")" \
      "cluster-id=$FC_CLUSTER_ID" \
      "tenant=$FC_TENANT" \
      "k8s-webhook-secret=$(read_val "$FC_K8S_WEBHOOK_SECRET" "$FC_K8S_WEBHOOK_SECRET_FILE")" \
      "git-credential=$(read_val "$FC_GIT_CREDENTIAL" "$FC_GIT_CREDENTIAL_FILE")" \
      "receiver-secret=$(read_val "$FC_RECEIVER_SECRET" "$FC_RECEIVER_SECRET_FILE")"
    gl="$(read_val "$FC_GITLAB_TOKEN" "$FC_GITLAB_TOKEN_FILE")"
    jk="$(read_val "$FC_JENKINS_CREDENTIAL" "$FC_JENKINS_CREDENTIAL_FILE")"
    if [[ -n "$gl$jk" ]]; then
      apply_secret "$FC_AGENT_NAMESPACE" fc-agent-ci \
        "gitlab-token=$gl" "jenkins-credential=$jk"
    fi
  else
    step "Verifying externally managed agent credentials"
    require_secret_keys "$FC_AGENT_NAMESPACE" fc-agent \
      fixcontrol-url agent-id agent-secret cluster-id tenant
  fi
fi

if [[ "$FC_INSTALL_TEST_RUNNER" == "1" ]]; then
  # The runner's namespace has to exist before its Secret can. It is a resource
  # in the base, so create it up front rather than ordering the apply.
  if ! kubectl get ns "$FC_TEST_RUNNER_NAMESPACE" >/dev/null 2>&1 && [[ "$DRY_RUN" != "1" ]]; then
    kubectl create ns "$FC_TEST_RUNNER_NAMESPACE"
    kubectl annotate ns "$FC_TEST_RUNNER_NAMESPACE" \
      fixcontrol.ai/created-by=fixcontrol-install --overwrite
  fi
  ensure_nonce_configmap "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner-nonces fc-test-runner
  if [[ "$FC_MANAGE_SECRETS" == "1" ]]; then
    step "Applying test-runner credentials"
    # envFrom: secretRef — the KEYS ARE THE ENV VAR NAMES here, which is why
    # they are spelled differently from the agent's per-key secretKeyRefs.
    apply_secret "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner \
      "FIXCONTROL_URL=$FC_URL" \
      "FIXCONTROL_AGENT_ID=$FC_TEST_RUNNER_AGENT_ID" \
      "FIXCONTROL_AGENT_SECRET=$(read_val "$FC_TEST_RUNNER_AGENT_SECRET" "$FC_TEST_RUNNER_AGENT_SECRET_FILE")" \
      "FIXCONTROL_CLUSTER_ID=$FC_CLUSTER_ID" \
      "FIXCONTROL_TENANT=$FC_TENANT"
  else
    step "Verifying externally managed test-runner credentials"
    require_secret_keys "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner \
      FIXCONTROL_URL FIXCONTROL_AGENT_ID FIXCONTROL_AGENT_SECRET \
      FIXCONTROL_CLUSTER_ID FIXCONTROL_TENANT
  fi
fi

# ── Apply ──────────────────────────────────────────────────────────────────
if [[ "$DRY_RUN" == "1" ]]; then
  step "Server-side dry-run (no writes)"
  kubectl apply -k "$RENDER" --dry-run=server
  exit 0
fi

step "Applying"
kubectl apply -k "$RENDER"

step "Waiting for rollout"
[[ "$FC_INSTALL_AGENT" == "1" ]] && \
  kubectl -n "$FC_AGENT_NAMESPACE" rollout status deploy/fc-agent --timeout=180s
[[ "$FC_INSTALL_TEST_RUNNER" == "1" ]] && \
  kubectl -n "$FC_TEST_RUNNER_NAMESPACE" rollout status deploy/fc-test-runner --timeout=180s

if [[ "$SKIP_VERIFY" == "1" ]]; then
  step "Installed (verify skipped)"
  exit 0
fi

step "Verifying"
exec "$HERE/verify.sh" --values "$VALUES"
