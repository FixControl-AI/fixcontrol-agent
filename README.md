# FixControl cluster agent

A single pod (`fc-agent`) that runs **in your cluster**, dials *out* to
FixControl over HTTPS, asks for signed operations, re-authorizes each one
locally against configuration **you** own, and executes it against your private
Kubernetes/Argo API — plus, optionally, a second pod (`fc-test-runner`) that
runs FixControl validation plans in ephemeral namespaces.

**The complete firewall requirement:** `egress customer → api.fixcontrol.ai:443`.
**The inbound requirement: none.** No Service, no Ingress, no LoadBalancer, no
inbound NetworkPolicy anywhere in this package. FixControl never dials in and
never learns your API server's address.

What the agent may do is bounded in three independent places, and the last one
is entirely yours:

1. the registration in FixControl grants a capability set;
2. every poll intersects that grant with what the running agent advertises —
   neither side can widen the other;
3. the allowlists in `values.env` (`FC_ALLOWED_NAMESPACES`,
   `FC_ALLOWED_ROLLOUTS`, `FC_ALLOWED_COMMANDS`, the image prefixes) live in
   **your** cluster. FixControl never sends them and cannot override them. An
   empty namespace allowlist allows *nothing*, and the installer refuses an
   install that leaves it empty by accident.

Full reference documentation: <https://fixcontrol.ai/docs/en/admin/fc-agent>

---

## 1. Get the package

Download the tarball from [the latest release](../../releases/latest), verify
it, and unpack it:

```sh
VERSION=1.0.3            # the release you are installing
base="https://github.com/FixControl-AI/fixcontrol-agent/releases/download/v${VERSION}"

curl -fsSLO "${base}/fixcontrol-agent-${VERSION}.tar.gz"
curl -fsSLO "${base}/fixcontrol-agent-${VERSION}.tar.gz.sha256"
sha256sum -c "fixcontrol-agent-${VERSION}.tar.gz.sha256"

tar xzf "fixcontrol-agent-${VERSION}.tar.gz"
cd "fixcontrol-agent-${VERSION}"
```

The images are published to `ghcr.io` and **signed**. Verify them before you
run them — the signature is keyless, so there is no key of ours you have to
trust or store:

```sh
curl -fsSLO "${base}/image-pins.env"     # the two digest-pinned lines values.env wants
. ./image-pins.env

cosign verify "$FC_AGENT_IMAGE" \
  --certificate-identity-regexp '^https://github.com/FixControl-AI/fixcontrol-agent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also ships CycloneDX SBOMs (`*.cdx.json`) and
`image-manifest.json` listing every digest.

**Building the images yourself** — for an air-gapped estate, or because you
would rather not pull ours — is supported and is why the sources are in this
tarball:

```sh
VERSION=${VERSION} REGISTRY=registry.internal/fixcontrol \
  ONLY=fc-agent,fc-test-runner ./scripts/build-images.sh
# writes build/image-pins.env with YOUR digests — use those below instead
```

## 2. Enrol the agent in FixControl

In FixControl: **Settings → DevOps**.

1. Connect **Kubernetes** if you have not already — an agent registration hangs
   off that connection, and enrolment refuses without one.
2. **fc-agents → Enrol.** Tick only the capabilities this cluster should hold;
   nothing is preselected, because "release a paused production deployment" is
   not a sensible default.
3. The screen then shows, **once**, a shared secret, and alongside it an
   assembled `values.env` block. Copy that block now — the secret is never
   readable again.

## 3. Fill in `values.env`

```sh
cp install/values.example.env install/values.env
chmod 600 install/values.env
$EDITOR install/values.env
```

Paste the block from enrolment (`FC_URL`, `FC_TENANT`, `FC_CLUSTER_ID`,
`FC_AGENT_ID`, `FC_AGENT_SECRET`, `FC_SIGNING_PUBLIC_KEYS`,
`FC_REQUIRE_SIGNING_PIN=1`), paste the two `FC_*_IMAGE` lines from
`image-pins.env`, and then make the four decisions that are yours alone. They
are documented where you make them; in short:

| Value | The decision |
|---|---|
| `FC_ALLOWED_NAMESPACES` | where this agent may act at all. Empty allows nothing. |
| `FC_PROMOTE_MODE` | `git` (a reviewable marker commit — the default and the strongest), `receiver`, or `none` for a CI-gate-only install. |
| `FC_EGRESS_*` | every destination this pod may reach, named. There is deliberately no spelling for `0.0.0.0/0`. |
| `FC_MANAGE_SECRETS` | whether `install.sh` owns the Kubernetes Secrets, or External Secrets / Vault does. |

`values.env` is gitignored, holds three credentials, and should stay `0600`.

## 4. Install

```sh
./install/install.sh --render-only   # read the YAML first, if you want to
./install/install.sh --dry-run       # server-side dry run, no writes
./install/install.sh                 # render → validate → apply → verify
```

It is a renderer plus `kubectl apply -k`: the complete overlay is written to
`install/.render/` as ordinary YAML you can read, diff, review, or commit to
your own GitOps repository. Re-running with an unchanged values file changes
nothing.

## 5. Verify

```sh
./install/verify.sh
```

Read-only, safe to re-run, and it **proves** rather than asserts: workloads
running on the pinned digest, RBAC positives *and* negatives, a NetworkPolicy
with no `0.0.0.0/0` and no Ingress, the admission policy demonstrated by making
the API server refuse four writes, and the signing pin read back out of the
running process.

Do not proceed while `verify.sh` is red. Every failure it reports is something
that would otherwise surface later as a deployment gate that silently never
ships.

---

## Day two

| Task | Command |
|---|---|
| Rotate the FixControl credential | `./install/rotate-agent-secret.sh` (rotate in FixControl first; never edit the Secret by hand) |
| Stop the cluster acting, now | `./install/revoke-agent.sh`, then **Revoke** in Settings → DevOps |
| Upgrade | download the new release, copy your `values.env` across, paste the new `image-pins.env` lines, re-run `install.sh` |
| Remove everything | `./install/uninstall.sh` — it removes, then proves nothing is left |

**Upgrades are ordinary.** The agent and FixControl negotiate capabilities on
every poll, so a newer server and an older agent keep working within the
capabilities both understand; a release that requires a newer agent says so in
its notes.

## What this package does NOT contain

- Any inbound listener, Service or Ingress.
- Any "run this command" operation. The operation vocabulary is closed:
  approve/reject a CI deployment, promote/abort/read an Argo rollout, run/cancel
  a validation.
- Any way for FixControl to widen your allowlists, skip TLS verification, or
  learn a credential you hold. Those are absences by design, and `verify.sh`
  demonstrates several of them against your live cluster.
