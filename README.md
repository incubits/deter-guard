# deter-guard

Egress control for CI. Fetches your organization's signed policy from
[console.deter.dev](https://console.deter.dev), verifies it, and runs your build behind a filtering
proxy — so a blocklisted package is never downloaded.

It pulls a **second** signed artifact alongside it: the packages your organization refuses to
install, malicious or vulnerable. See
[Blocking malicious and vulnerable packages](#blocking-malicious-and-vulnerable-packages).

```
ghcr.io/incubits/deter-guard
```

One static Go binary in a ~6 MB `scratch` image. No shell, no package manager, no runtime, no
dependencies (`go.mod` has no `require` block).

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
          console: https://console.deter.dev
          pubkey: ${{ vars.DETER_POLICY_PUBKEY }}   # see "Pin the public key"

      - run: pnpm install --frozen-lockfile   # guarded
      - run: pnpm build                       # guarded
```

The action pulls the guard, verifies its build provenance, starts it, and shuts it down cleanly at
the end of the job (pass, fail, or cancel) so refusals are flushed and refused hosts appear as
annotations on the run summary.

> **First run?** Claim your GitHub organization at
> [console.deter.dev](https://console.deter.dev) → **CI protection → Trusted CI owners**. Until you
> do, the OIDC exchange is refused by design.
>
> Then add `mode: monitor` for the first few runs. The job reports what the policy *would* have
> refused and blocks nothing, so you find out what your build actually talks to without finding out
> the hard way. See [Monitor first, then enforce](#monitor-first-then-enforce).

### Anywhere else

```bash
export DETER_CONSOLE_URL=https://console.deter.dev
export DETER_POLICY_PUBKEY=<hex>      # see "Pin the public key"

deter-guard exec -- npm ci
```

```
deter-guard: policy version 812 verified against pinned key a092bf20…1b26d0f8
deter-guard: egress proxy on http://127.0.0.1:52054 · 4 rule(s), 118 block(s)
deter-guard: DENY  GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz — on your blocklist
npm error 403 Forbidden - GET https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
```

### In your own image

One `COPY`. The binary is static and carries its own root certificates, so it needs nothing from the
image it lands in:

```dockerfile
COPY --from=ghcr.io/incubits/deter-guard:latest /deter-guard /usr/local/bin/deter-guard
```

GitLab, Jenkins, air-gapped runners, sidecars and PID-1 setups:
[docs/reference.md](docs/reference.md).

## Policy lives in the console

You author policy at [console.deter.dev](https://console.deter.dev); the guard only enforces what it
is handed. Nothing to commit, nothing to redeploy — every job picks up the current version on its
next run.

| In the console | What it means here |
| --- | --- |
| **Egress policy → rules** | Permit a host, optionally narrowed to methods and path prefixes. Default deny: no rule, no request. |
| **Egress policy → blocklist** | Deny a host or a path glob *even when a rule permits the host*. Checked first — a permit can't override it. |
| **CI protection → Trusted CI owners** | Claim an org, so its pipelines' OIDC tokens are accepted. |
| **CI protection → CI tokens** | `dtrc_` tokens for platforms that can't mint OIDC. |
| **Connect → Key fingerprint** | The public key you pin. |

A rule can be disabled without being deleted; disabled rules travel with the policy so the console
can show them, and are never enforced.

### Pin the public key

`DETER_POLICY_PUBKEY` is the difference between a real check and a decorative one.

Without it the guard still verifies the signature — but against the key **the console just handed
it**, which only proves the bundle agrees with itself. Anything able to serve the bundle can serve a
matching key. The guard says so on every run:

```
deter-guard: key was NOT pinned — this proves the bundle is self-consistent, not that it came
from you. Set DETER_POLICY_PUBKEY to make this a real check.
```

Copy it from **Connect → Key fingerprint**. It's a public key: commit it, put it in a CI variable,
print it in logs.

## Monitor first, then enforce

```bash
deter-guard exec --mode monitor -- npm ci
```

Nobody knows every host their build touches, and the first pipeline anyone wants a policy on is the
one they cannot afford to break. Turning enforcement on blind means a red build, an urgent revert,
and a control that is now switched off. **A policy nobody dares enable protects nothing.**

| | `--mode monitor` | `--mode enforce` (default) |
| --- | --- | --- |
| The decision | made, logged, reported | made, logged, reported |
| The request | goes through | **403**, never dialled onward |
| Your build | passes | fails at the first refused fetch |

Monitor mode is the run that produces the list. The per-request lines are lost in forty thousand
lines of build output, so it ends with a summary: identical refusals collapsed, so a retry loop is
one row rather than four hundred, in first-seen order — the first thing refused is usually what
caused everything after it.

```
deter-guard: MONITOR MODE SUMMARY: 12 request(s) across 3 target(s) WOULD have been refused (431 allowed by the policy). Nothing was blocked:
deter-guard:        9 × GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz — left-pad 1.3.0 is on your organization's blocklist
deter-guard:        2 × CONNECT telemetry.example.com:443 — host not permitted by the egress policy
deter-guard:        1 × GET telemetry.example.com/v1/events — host not permitted by the egress policy
```

**It is the same code path, not a simulator.** The policy is consulted and the refusal is built
either way; the only branch is whether the 403 is written or the request is let through. A dry run
that re-implemented the decision would eventually disagree with the one that enforces, and you would
find out in the direction of a broken build.

Refusals reach the console in both modes — the batch carries the mode, so an observation is not
counted as a block — and on GitHub Actions they arrive as **warning** annotations rather than errors.

One input on Actions (`mode: monitor`), `--mode monitor` or `DETER_MODE` anywhere else. Flipping a
whole organization with one variable, and what stays refused even in monitor mode, are in
[docs/reference.md#monitor-mode](docs/reference.md#monitor-mode).

> **A job in monitor mode is not protected.** It is a measurement, and it looks exactly like a
> guarded job apart from the one property that matters. Move it to `enforce` once the list is empty.

## How it works

Two decision points, and the split is the product:

| | Decided on |
| --- | --- |
| `CONNECT host:443` | host only — a tunnel has no method or path yet |
| every request inside it | host + method + **path**, after TLS is terminated |

**This is why a blocklist can name a package version.** `registry.npmjs.org` stays reachable while
one compromised tarball does not. Deciding only at the tunnel can't do that: a rule scoped to `/v1/*`
has nothing to match at CONNECT time, so either the whole host is refused or the rule silently does
nothing.

Matching on the path needs TLS interception, so a CA is generated in memory per run, written only
where the build is told to trust it, and dies with the job.

### Proxy or transparent

How traffic *reaches* the guard. Independent of [monitor or
enforce](#monitor-first-then-enforce) — the two compose, and any combination is valid.

| | Proxy (default) | Transparent |
| --- | --- | --- |
| Command | `exec`, `serve` | `serve --transparent --redirect --install-ca` |
| Build is pointed at it by | `HTTPS_PROXY` and friends | the kernel redirects :80/:443 |
| Needs | nothing | Linux + root (`transparent: true` on Actions) |
| Can a process opt out? | **yes** | no |

`HTTPS_PROXY` is a *request*. npm, pip, curl and git honour it; a malicious `postinstall` that opens
its own socket does not. That matters less than it sounds — the proxy sits where packages are
**fetched**, so a blocked package is never downloaded and its install script never runs — but proxy
mode is filtering, not containment, and shouldn't be described to an auditor as containment.
Transparent mode is containment, with caveats worth reading first:
[docs/reference.md#transparent-mode](docs/reference.md#transparent-mode).

## Blocking malicious and vulnerable packages

Seeing the path is what makes this possible, so the guard also pulls your organization's signed
**supply-chain document** and decides every tarball fetch against it. Nothing to configure: it is on
by default wherever the guard already talks to a console.

```
deter-guard: supply-chain blocklist version 1789234440 verified against pinned key a092bf20…1b26d0f8
deter-guard:   232994 entries · malware=enforce tail=enforce · cve=high/enforce+kev
deter-guard: DENY  GET registry.npmjs.org/vite/-/vite-6.2.1.tgz — vite@6.2.1 is blocked —
             GHSA-4r4m-qw57-chr8 (MODERATE): confirmed exploited in the wild (CISA KEV). Fixed in 6.2.4
```

Two matchers, because the corpus has two shapes:

| | |
| --- | --- |
| **Malware** | Set membership. Either every version of a package is malicious (a typosquat) or one exact release of a real package is (the Shai-Hulud shape). No version arithmetic. |
| **Vulnerabilities** | Semver **ranges**, evaluated here. Expanding ~9,900 range lines to concrete versions measures ~341,000 pairs — 34× larger, and stale the moment a version is published into an unfixed range. |

**Only tarball fetches are decided.** Metadata requests stay allowed, or dependency resolution breaks
long before it ever reaches the version that would be refused — and a blocklist that also broke
`npm view` is one you'd switch off by the end of the week.

**The posture travels with the data.** Thresholds, which classes enforce and which only report, the
CISA KEV override, mirror prefixes — all of it is in the document's header, configured per surface in
the console. Moving from `high` to `critical`, or excusing one pipeline, is a new document, not a new
guard release.

### It fails **open**, loudly

The egress policy fails closed — no policy means no egress, which is what an egress policy is for.
This artifact is the opposite, deliberately. It changes every fifteen minutes as feeds move, and a
console outage must not break every `npm ci` you run. So **every** failure here degrades package
blocking, says so in the build log, and leaves the egress policy untouched — an unreachable console,
an unpublished document, a signature that does not verify, no key to verify against. The
[failure table](docs/reference.md#supply-chain) says what each one prints.

Turn it off entirely with `--no-supply-chain`, or `supply-chain: false` on the action.

`--mode monitor` still outranks everything: nothing is blocked on that run, whatever the document
says. Independently of that, your organization can put one class on `monitor` while another enforces
— and an advisory with **no fixed version** is reported rather than blocked by default, because
blocking a package with nowhere to upgrade to is how a control gets switched off wholesale instead of
tuned.

## What a refusal looks like

A real HTTP **403**, delivered inside the TLS session:

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

A package refused by the supply-chain blocklist answers with the same status and a body built to be
read in `npm install` output — what, why, and where to go next:

```json
{
  "error": "package_blocked",
  "decision": "deny_supply_chain",
  "reason": "vite@6.2.1 is blocked — GHSA-4r4m-qw57-chr8 (MODERATE): confirmed exploited in the wild (CISA KEV). Fixed in 6.2.4",
  "package": "vite",
  "package_version": "6.2.1",
  "advisory": "GHSA-4r4m-qw57-chr8",
  "fixed_in": "6.2.4",
  "kev": true,
  "fix": "upgrade to 6.2.4 — or, if that is not possible yet, ask an admin for an exception under Supply chain in the deter console"
}
```

The same facts are on `X-Deter-Package`, `X-Deter-Advisory` and `X-Deter-Fixed-In`. The fix named is
the one for the **branch** the blocked version is on: an advisory spanning majors carries a fix per
branch, and telling someone on 6.2.1 to "upgrade" to 4.5.11 is a downgrade across two majors —
wrong advice in a denial is worse than none. Every field is in
[docs/reference.md#supply-chain](docs/reference.md#supply-chain).

Nothing is sent to the refused host — the tunnel is terminated here and never dialled onward.
Under `--mode monitor` this response is never written: the same decision is logged and reported, and
the request goes through.

**The status code is the point.** Refusing at `CONNECT` gives the client a *transport* error, and
every package manager retries those with backoff for minutes against a host that will never answer.
None of them retry a 4xx: `pnpm install` against a refused registry fails in one second with
`ERR_PNPM_FETCH_403`.

## CLI

| Command | |
| --- | --- |
| `deter-guard exec -- <cmd>` | Run `<cmd>` behind the proxy. Exit code passes straight through. |
| `deter-guard serve` | Run the proxy on its own, so many commands sit behind one. |
| `deter-guard env` | Print the variables that point a build at a running proxy. |
| `deter-guard whoami` | What this pipeline authenticates as. Run it first when something's wrong. |
| `deter-guard policy` | Fetch, verify, and write the policy. `--out <path>`, or stdout. |
| `deter-guard claim` | Finish claiming an organization. On Actions use `uses: incubits/deter-guard/claim@v1`. |

`--json` on `claim`, `whoami` and `policy`. Every flag: `deter-guard --help`, or
[docs/reference.md](docs/reference.md).

## Configuration

| Env | Flag | |
| --- | --- | --- |
| `DETER_CONSOLE_URL` | `--console` | `https://console.deter.dev`. Required. |
| `DETER_POLICY_PUBKEY` | `--pubkey` | Pin the signing key. Strongly recommended. |
| `DETER_ID_TOKEN` | | An OIDC ID token you supply (GitLab and friends). |
| `DETER_CI_TOKEN` | | A long-lived `dtrc_` token. Fallback only. |
| `DETER_MODE` | `--mode` | `enforce` (default) or `monitor`. |
| `DETER_POLICY_FILE` | `--policy` | Enforce a local, **unsigned** policy file. Testing and air-gapped runners. |
| `DETER_NO_SUPPLY_CHAIN` | `--no-supply-chain` | Don't block malicious or vulnerable packages at all. |

Credentials are tried in order: `DETER_ID_TOKEN` → GitHub Actions OIDC → `DETER_CI_TOKEN`. If the
OIDC exchange is *rejected* (wrong audience, owner not claimed) the guard does **not** fall back to a
`dtrc_` token — that would hide a real misconfiguration behind a different credential.

The [full list](docs/reference.md#environment) covers the `serve` and transparent-mode knobs.

## Exit codes

Distinct on purpose — a pipeline shouldn't have to grep stderr.

| | |
| --- | --- |
| `0` | Fine. |
| `1` | Usage or configuration problem. |
| `2` | **The policy did not verify.** Nothing was written. Treat as a compromised distribution path until proven otherwise. |
| `3` | Auth failed — including being over a plan limit (the message names the meter). |

## Versions

The action and the image are one release from one commit, so **pinning the action pins the binary**:
the default image is derived from the ref after the `@`.

```
uses: incubits/deter-guard@v1         # newest 1.x
uses: incubits/deter-guard@v1.4.2     # exactly that
ghcr.io/incubits/deter-guard:latest   # newest release — what the examples here use
ghcr.io/incubits/deter-guard:1        # the image, same shape as the action
```

The action examples say `@v1` and the image examples `:latest`, which is not the inconsistency it
looks like: a workflow can only resolve a branch, a tag or a SHA, and there is no `latest` **tag** —
`uses: …@latest` fails to resolve — while the registry does have a `:latest`.

Verify where the image came from:

```bash
gh attestation verify oci://ghcr.io/incubits/deter-guard:latest --repo incubits/deter-guard
```

Details, and the `:latest` vs `:main` distinction, in
[docs/reference.md#versions](docs/reference.md#versions).

## Development

```bash
go test ./... && go vet ./...
node --test action/inputs.test.js  # the action is JavaScript; `go test` never sees it
node --test ci/semantic.test.js    # the naming and version rules
go build -o deter-guard .          # local binary
docker build -t deter-guard:dev .  # the scratch image
```

Branch and commit naming, and how a release is cut, are in [CONTRIBUTING.md](CONTRIBUTING.md) — both
are enforced in CI because `VERSION` is checked against them. Known gaps and open work are in
[TODO.md](TODO.md).

Nothing here depends on the console's source. The verifier is a deliberate re-implementation — a CI
runner shouldn't pull in a web framework and a database driver to check a signature — and a test pins
the signed-payload format against a vector produced by the console's own signer, which the broker's
Rust verifier is also pinned against. Three implementations, one signature.
