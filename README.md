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
| `deter-guard serve` | Run the proxy as a process in its own right, so many commands can sit behind one proxy. |
| `deter-guard env` | Print the variables that point a build at a running proxy. |

`--json` on `whoami`/`policy` for machine-readable output.

### exec and serve options

| | |
| --- | --- |
| `--policy <path>` | Enforce a local policy file instead of fetching one. **Unsigned** — nothing is verified, so it says so on every run. For testing and air-gapped runners. |
| `--state-dir <dir>` | Where the CA the build must trust is written. Defaults to a temp dir. |
| `--verbose` | Log allowed requests too, not just refusals. |

### serve options

| | |
| --- | --- |
| `--addr <ip>` | Listen address. Default `127.0.0.1`. Anything else is warned about loudly — see below. |
| `--port <n>` | Listen port. Default `3128`; `0` lets the kernel pick a free one. |
| `--ca-out <path>` | Write the CA here, and leave it there on exit. |
| `--ready-file <p>` | Write the proxy URL here once the socket is actually accepting. |
| `--detach` | Background the proxy; return only once it is up. |
| `--wrap` | Run one command on a fixed port, then shut down. |

### env options

| | |
| --- | --- |
| `--format <fmt>` | `sh` (default), `github`, `docker`, `json`. |
| `--proxy <url>`, `--ca <path>` | Override. By default both are read from the running guard's state file. |
| `--unset` | Emit lines that *clear* the variables instead of setting them. |

The proxy is configured for the build through the environment — `HTTPS_PROXY` and friends, plus
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`,
`SSL_CERT_FILE` and `CARGO_HTTP_CAINFO`. Missing one of those shows up as an inscrutable certificate
error deep inside a package manager, so they are all set. `deter-guard env` prints exactly that list,
which is why it exists: a list copied into your repository stops matching ours the next time it grows.

## Adding the guard to an image you already build

One `COPY`. The binary is static and carries its own root certificates, so it does not need a CA
bundle, a libc, or anything else from the image it lands in:

```dockerfile
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard
```

There are three ways to put it in front of a build. They differ in how hard it is for the build to
get around, so pick by what you are defending against.

### 1. Wrap each command — `exec`

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard
RUN deter-guard exec -- npm ci
```

Simplest, and scoped to exactly the command you name. The cost is a prefix on every line.

### 2. One proxy, many commands — `serve`

For a developer image where people run whatever they like and you still want the traffic filtered,
put the guard at PID 1 and let everything inherit it:

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard

# A FIXED port and CA path, so these values can be baked in — which is what makes
# `docker exec` into a running container covered too, not just the CMD.
ENV DETER_GUARD_PORT=3128 DETER_GUARD_CA_OUT=/etc/deter/ca.pem
ENV HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128 \
    http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128 \
    NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1 \
    NODE_EXTRA_CA_CERTS=/etc/deter/ca.pem SSL_CERT_FILE=/etc/deter/ca.pem \
    REQUESTS_CA_BUNDLE=/etc/deter/ca.pem PIP_CERT=/etc/deter/ca.pem \
    CURL_CA_BUNDLE=/etc/deter/ca.pem GIT_SSL_CAINFO=/etc/deter/ca.pem \
    CARGO_HTTP_CAINFO=/etc/deter/ca.pem DETER_GUARD_CA=/etc/deter/ca.pem

ENTRYPOINT ["deter-guard", "serve", "--wrap", "--"]
CMD ["bash"]
```

`deter-guard env --format docker` prints that `ENV` block, so you do not have to keep it in step by
hand.

In CI, the same idea without a container — start it once, then every later step is guarded with no
prefix:

```yaml
- run: deter-guard serve --detach
- run: deter-guard env --format github >> "$GITHUB_ENV"
- run: pnpm install --frozen-lockfile
- run: pnpm build
- run: pkill -TERM deter-guard || true   # lets it flush its report
  if: always()
```

Shut it down rather than letting the job reap it: refusals are flushed on `SIGTERM`, so a guard that
is killed outright enforces correctly and tells the console nothing.

### 3. A sidecar that owns the network — strongest

Run the guard in its own container and give the build container no route out except through it
(`network_mode: service:guard` in Compose, or one Pod with two containers). The build cannot stop the
proxy, cannot rewrite its rules, and cannot un-set its way around it, because none of it is in its
container.

```yaml
services:
  guard:
    image: ghcr.io/incubits/deter-guard:latest
    command: ["serve", "--addr", "0.0.0.0", "--port", "3128", "--ca-out", "/shared/ca.pem"]
    volumes: ["shared:/shared"]
  build:
    image: your-build-image
    network_mode: "service:guard"
    volumes: ["shared:/shared"]
```

`--addr 0.0.0.0` publishes an intercepting proxy with no authentication on it, so the guard warns
every time you do it. Publish it to one build's network, never to a shared one.

### How much any of this is worth

Shapes 1 and 2 point the build at the proxy with environment variables, and a variable is a
*request*: a package's install script that opens its own socket, ignoring `HTTPS_PROXY`, is not
stopped by either. That is still the control that matters for the main threat, because it sits where
packages are **fetched** — a package that is never downloaded never runs its install script.

Shape 3 is the one that holds against a process actively trying to get out, and only if the build
container genuinely has no other route. Do not describe shapes 1 and 2 to your auditors as
containment.

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
| `DETER_POLICY_FILE` | `--policy` | Enforce a local, **unsigned** policy file. |
| `DETER_STATE_DIR` | `--state-dir` | Where the CA and the state file go. |
| `DETER_GUARD_ADDR` | `--addr` | `serve` listen address. Default `127.0.0.1`. |
| `DETER_GUARD_PORT` | `--port` | `serve` listen port. Default `3128`. |
| `DETER_GUARD_CA_OUT` | `--ca-out` | Where `serve` writes the CA, and leaves it. |
| `DETER_GUARD_ROOTS` | | Roots for the guard's *own* TLS: `both` (default), `system`, `embedded`. |

Credentials are tried in order: `DETER_ID_TOKEN`, then GitHub Actions OIDC, then `DETER_CI_TOKEN`.

`DETER_GUARD_ROOTS` deserves a note. The binary embeds Mozilla's root set so that copying it into a
slim image — one that carries no CA bundle, because its language runtime ships its own — does not
silently break the guard's own outbound TLS. By default those roots are a **union** with the host's
store, which means a root the host has deliberately distrusted stays trusted here until the guard is
rebuilt. Set `system` to use only the host's trust decisions and fail honestly when there are none,
or `embedded` for a set that does not vary with the base image. None of this affects what the *build*
may reach: that is the policy, checked before any connection is made.

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

- **Transparent interception.** `exec` and `serve` filter what is *sent* through the proxy; neither
  stops a process from ignoring `HTTPS_PROXY` and opening its own socket. The sidecar shape above
  closes that off at the network layer today, but it takes a second container and a shared network
  namespace. Doing it inside one container means redirecting outbound 80/443 with nftables and
  reading the SNI off a raw `ClientHello` — the proxy is CONNECT-only right now, so this is real work
  rather than a flag. See [What it does not do](#what-it-does-not-do).
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
