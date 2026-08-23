# deter-guard

Egress control for a CI job: fetch and verify the organization's signed policy, then **run the build
behind a filtering proxy** so a blocklisted package is never downloaded.

```
ghcr.io/incubits/deter-guard
```

A ~6 MB `scratch` image: one static binary, a CA bundle, and a passwd entry. No shell, no package
manager, no language runtime, no dependencies — `go.mod` has no `require` block, because ed25519,
JSON and TLS are all in the Go standard library.

## What this does

`deter-guard exec` starts a local proxy, points the build at it, and decides every request:

```
deter-guard exec -- npm ci
```

```
deter-guard: policy version 812 verified against pinned key a092bf20…1b26d0f8
deter-guard: egress proxy on http://127.0.0.1:52054 · 4 rule(s), 118 block(s)
deter-guard: DENY  GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz — on your blocklist
npm error 403 Forbidden - GET https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
```

Two decision points, and the split matters:

| | Decided on |
| --- | --- |
| `CONNECT host:443` | host — a tunnel has no method or path yet |
| every request inside it | host + method + **path**, after TLS is terminated |

Deciding only at the tunnel is what makes path rules unenforceable: a rule scoped to `/v1/*` has
nothing to match at CONNECT time, so either the whole host gets refused or the rule does nothing.
Both are wrong and both are silent. So the tunnel opens if the host is plausibly reachable, and each
request inside it is checked properly.

**This is why a blocklist can name a package version.** `registry.npmjs.org` stays reachable while
one compromised tarball does not — which needs the path, which needs TLS interception. A CA is
generated in memory per run, written only where the build is told to trust it, and dies with the job.

### What it does not do

**It cannot filter what refuses to use it.** `HTTPS_PROXY` is a request. npm, pip, curl and git all
honour it — but a malicious `postinstall` can simply not.

That matters less than it sounds, because the proxy sits where packages are **fetched**: a blocked
package is never downloaded, so its install script never runs. The gap is the second case only —
code already executing that ignores the proxy. Closing it needs default-deny egress, which the
container can enforce on itself:

An entrypoint holding `CAP_NET_ADMIN` can put the job's own network namespace in default-deny and
then **drop privileges before running the build**. The build inherits the namespace, so the rules
apply to it, but not the capability, so it cannot remove them. Two things decide whether that holds:

- **The capability must be granted from outside** — `--cap-add=NET_ADMIN`, or
  `securityContext.capabilities`. Nothing inside an image grants it to itself. On GitHub Actions it
  goes in `container.options`, which allows it — unlike `--network`, one of the two options Actions
  forbids.
- **The build must not keep it.** A build running as root with `CAP_NET_ADMIN` just flushes the rules
  and walks out. The privilege drop *is* the control.

`deter-guard` does not install those rules yet. Until it does, treat `exec` as strong filtering of
cooperative tools — which is the whole acquisition half of a supply-chain attack — and not as a
sandbox.

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
| `deter-guard policy` | Fetch, verify, and write the Cedar policy. `--out <path>`, or stdout. |
| `deter-guard exec -- <cmd>` | Run `<cmd>` behind the filtering proxy. The command's exit code is passed straight through. |

`--json` on `whoami`/`policy` for machine-readable output.

### exec options

| | |
| --- | --- |
| `--policy <path>` | Enforce a local policy file instead of fetching one. **Unsigned** — nothing is verified, so it says so on every run. For testing and air-gapped runners. |
| `--state-dir <dir>` | Where the CA the build must trust is written. Defaults to a temp dir. |
| `--verbose` | Log allowed requests too, not just refusals. |

`exec` needs the build tooling in the same container, so the usual shape is to copy the binary into
your own image rather than run this one:

```dockerfile
FROM node:22-alpine
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard
```

The proxy is configured for the child through the environment — `HTTPS_PROXY` and friends, plus
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
`SSL_CERT_FILE` and `CARGO_HTTP_CAINFO`. Missing one of those shows up as an inscrutable certificate
error deep inside a package manager, so they are all set.

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

- **Default-deny egress.** `exec` filters what is sent through the proxy; it does not yet stop a
  process from ignoring it. See [What it does not do](#what-it-does-not-do) — the mechanism is known,
  it just is not wired up.
- **A blocklist feed.** The client already understands and enforces `blocked` entries, and the
  console already serves the field — but nothing populates it yet. Once a feed lands, every job
  picks it up on its next run with no change here.

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
