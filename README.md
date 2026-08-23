# deter-guard

The image a CI job runs to fetch **and verify** its organization's signed egress policy.

```
ghcr.io/incubits/deter-guard
```

A ~6 MB `scratch` image: one static binary, a CA bundle, and a passwd entry. No shell, no package
manager, no language runtime, no dependencies — `go.mod` has no `require` block, because ed25519,
JSON and TLS are all in the Go standard library.

## What this does — and what it does not

**It does not filter your traffic.** Running `deter-guard policy` and then `npm install` in the same
job installs whatever npm wants. The guard *delivers and verifies the policy*; it is not in the
network path.

Actually controlling egress needs three things, and the guard is only the first:

| | |
| --- | --- |
| 1. The policy, verified | **this image** |
| 2. A proxy enforcing it | the `deter` broker, running alongside the job |
| 3. No way around the proxy | network-level default-deny, so the proxy is the only route out |

Step 3 is the one people skip. `HTTPS_PROXY` is a *request* — npm and pip honour it, but a malicious
`postinstall` script can simply not. Without egress actually being denied at the network layer, a
proxy is a monitoring tool, not a control.

So today this image gives a pipeline the same signed policy a developer's sandbox pulls, and gets it
there safely. Enforcing it inside CI is the next piece of work, not something you get by adding this
step.


On GitHub Actions it mints its own OIDC token, so **there is no secret in the pipeline to leak**.
Elsewhere you pass an ID token or a long-lived `dtrc_` token from the console.

This is the CI-side client for [deter](https://github.com/incubits/deter)'s control plane. It's a
separate repository from the console on purpose: the guard is the part that runs inside *your*
pipeline, so it should be auditable, and a build provenance attestation is only worth having if you
can verify it against a repository you can read.

## Quick start

### GitHub Actions

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # required — without it GitHub won't mint an OIDC token
    container:
      image: ghcr.io/incubits/deter-guard:1
    steps:
      - run: deter-guard policy --out egress.cedar
        env:
          DETER_CONSOLE_URL: https://console.example.com
          DETER_POLICY_PUBKEY: ${{ vars.DETER_POLICY_PUBKEY }}
```

Claim your GitHub organization first, under **CI protection → Trusted CI owners**. Without that the
exchange is refused — that's the point: a credential from an org you haven't claimed can't be used.

### GitLab CI

GitLab requires the job to *declare* its ID token, so hand it over as `DETER_ID_TOKEN`:

```yaml
policy:
  image: ghcr.io/incubits/deter-guard:1
  id_tokens:
    DETER_ID_TOKEN: { aud: "deter-console" }
  variables:
    DETER_CONSOLE_URL: https://console.example.com
  script:
    - deter-guard policy --out egress.cedar
```

### Anything else (Jenkins, on-prem, air-gapped)

Mint a CI token in the console under **CI protection → CI tokens**, then:

```bash
docker run --rm \
  -e DETER_CONSOLE_URL=https://console.example.com \
  -e DETER_CI_TOKEN="$DETER_CI_TOKEN" \
  -e DETER_POLICY_PUBKEY="$DETER_POLICY_PUBKEY" \
  -v "$PWD:/workspace" \
  ghcr.io/incubits/deter-guard:1 \
  policy --project "$JOB_NAME" --run "$BUILD_TAG" --out /workspace/egress.cedar
```

`--project` and `--run` matter for a `dtrc_` token: the project is what usage is attributed to, and
the run is the idempotency key, so a retried job isn't counted twice. An OIDC session carries both
already.

## Pin the public key

`DETER_POLICY_PUBKEY` is the difference between a real check and a decorative one.

Without it the guard still verifies the signature — but against the key **the server just handed
it**, which proves only that the bundle is self-consistent. Anything able to serve the bundle can
serve a matching key. It says so on every run:

```
deter-guard: key was NOT pinned — this proves the bundle is self-consistent, not that it came
from you. Set DETER_POLICY_PUBKEY to make this a real check.
```

Get the key from **Connect → Key fingerprint**, or `curl https://<distribution-host>/egress-policy.pub`.
It's a public key: commit it, put it in a CI variable, print it in logs. That's fine.

## Commands

| | |
| --- | --- |
| `deter-guard whoami` | What this pipeline authenticates as. Run it first when something's wrong. |
| `deter-guard policy` | Fetch, verify, and write the policy. `--out <path>`, or stdout. |

`--json` on either for machine-readable output.

## Exit codes

Distinct on purpose — a pipeline shouldn't have to grep stderr to know what happened.

| Code | Meaning |
| --- | --- |
| `0` | Fine. |
| `1` | Usage or configuration problem. |
| `2` | **The policy did not verify.** Nothing was written. Treat as a compromised distribution path until proven otherwise. |
| `3` | Authentication or authorization failed — including being over a plan limit (the message names the meter). |

## Configuration

| Env | Flag | |
| --- | --- | --- |
| `DETER_CONSOLE_URL` | `--console` | Console base URL. Required. |
| `DETER_POLICY_PUBKEY` | `--pubkey` | Pin the signing key. Strongly recommended. |
| `DETER_ID_TOKEN` | | An OIDC ID token you supply (GitLab and friends). |
| `DETER_CI_TOKEN` | | A long-lived `dtrc_` token. Fallback only. |
| `DETER_CI_OIDC_AUDIENCE` | `--audience` | Default `deter-console`. Must match the console. |
| `DETER_PROJECT` | `--project` | Project id, for a `dtrc_` token. |
| `DETER_RUN_ID` | `--run` | Run id — deduplicates usage across retries. |

Credentials are tried in order: `DETER_ID_TOKEN`, then GitHub Actions OIDC, then `DETER_CI_TOKEN`.

If the OIDC exchange is *rejected* (wrong audience, owner not claimed) the guard does **not** fall
back to a `dtrc_` token — that would hide a real misconfiguration behind a different credential.

## Verify the image

Built by GitHub Actions with a provenance attestation, so you can prove where it came from:

```bash
gh attestation verify oci://ghcr.io/incubits/deter-guard:latest --repo incubits/deter-guard
```

Pin `sha-<commit>` in a pipeline if you want an immutable tag.

> **Maintainers:** a GHCR package published by Actions starts **private**, even from a public
> repository — it does not inherit repo visibility. Until it's switched, an anonymous
> `docker pull` gets a `401`. Flip it once, in
> [Packages → deter-guard → Package settings → Change visibility](https://github.com/orgs/incubits/packages/container/deter-guard/settings).

## Not here yet

Two things, both flagged above:

- **Enforcement inside CI.** The guard delivers the policy; nothing in this image puts it in the
  network path. That needs the broker running alongside the job *and* egress denied at the network
  layer — see [What this does](#what-this-does--and-what-it-does-not).
- **Blocking malicious package versions.** Needs `/api/ci/blocklist`, which the console doesn't serve
  yet. `deter-guard blocklist` slots in beside `policy` when there's a list to fetch.

## Building locally

```bash
go test ./...
go vet ./...
go build -o deter-guard .          # a local binary
docker build -t deter-guard:dev .  # the scratch image
```

Go cross-compiles, so the multi-arch image needs no QEMU: the Dockerfile runs the compiler natively
on the builder and targets each platform via `GOOS`/`GOARCH`. An arm64 image costs seconds rather
than minutes of emulation.

Nothing here depends on the console's source. The verifier is a deliberate re-implementation — a CI
runner shouldn't pull in a web framework and a database driver to check a signature — and a test
pins the signed-payload format against a vector produced by the console's own signer, which the
broker's Rust verifier is also pinned against. Three implementations, one signature.
