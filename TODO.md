# TODO

Findings from a review of `main` that are not yet fixed. Two rounds of fixes are not repeated here:
the egress bypasses from the first review — the `Host` header defeating wildcard rules, and
non-canonical paths walking past the blocklist — are fixed in `canonical.go`; the transparent-mode
findings from the second — IPv6 going uncovered, cloud metadata exempted from filtering, and shape 4
claiming a containment it did not provide — are fixed in `redirect.go` and `dropprivs.go`.

Ordered by what it costs to be wrong about them, not by effort.

## Security

### Rollback protection on the signed policy

`Version` is covered by the ed25519 signature but never compared against anything, and nothing is
persisted between runs. A **previously valid** bundle therefore verifies forever: anyone who can
serve one — a compromised CDN, an MITM on the console — downgrades an organization to yesterday's
blocklist without breaking a single signature check. The whole point of the blocklist is that it
gets *newer*.

Cheapest closure is a floor: `--min-version` / `DETER_POLICY_MIN_VERSION`, refusing anything below
it. A run that remembers the highest version it has seen (in the state dir) would be better still,
but the floor is the part that can ship this week.

### `govulncheck` in CI

"No dependencies, so nothing to patch" is true of the module graph and false of the binary. This
program's attack surface is almost entirely standard library — `crypto/tls`, `net/http`,
`net/url`, `encoding/json` — and a stdlib CVE lands here the same as anywhere. `govulncheck` is
the one check that covers the blind spot in the claim the README makes, and it needs no
dependencies of its own.

### `SECURITY.md`

A security product with no disclosure policy. Someone who finds the next one of these has nowhere
to send it except a public issue.

### The query string is invisible to policy

Every decision is made on the path alone: `Check(host, method, path)` never sees `RawQuery`. A
blocklist cannot name an artifact that is identified in the query — `?version=`, `?file=` — which
is how a fair number of private registries and artifact proxies address downloads.

This is a policy-model change, not a bug fix: the console has to be able to express it before the
client can enforce it. Worth deciding deliberately rather than leaving implicit.

## Supply chain of the guard itself

### Digest-pin the base images

`image.yml` pins every third-party action to a commit SHA, and then the Dockerfile pulls
`golang:1.25-alpine` and `alpine:3.21` by mutable tag. For a tool whose pitch is provenance, that
is the inconsistency a customer will notice first.

### Publish an SBOM alongside the provenance attestation

`docker/build-push-action` takes `sbom: true` and `provenance: mode=max`. One line each, and it is
the next thing anyone verifying the image asks for.

### `LICENSE`

There isn't one. The provenance story depends on this repo being public and readable, and nothing
currently says what anyone may do with what they read.

## Correctness and operability

### The CI session token is never refreshed

`ciSession.ExpiresIn` is parsed and then never used. `exec` authenticates once at startup and holds
that token for the life of the build, so a build longer than the session simply stops being able to
report: the console answers 401, and `post` correctly declines to retry a 4xx. Filtering is
unaffected, which is why nobody notices — the refusals just quietly stop arriving.

### `exec` never re-fetches the policy

A blocklist entry published mid-build is not picked up until the next run. That is a defensible
decision; it is not a documented one.

### No upstream-proxy chaining

`Proxy: nil` on the upstream transport is deliberate and right as a default, but it means
deter-guard cannot run on a corporate runner that mandates an egress proxy of its own. Needs an
explicit `--upstream-proxy` rather than silently inheriting `HTTPS_PROXY`.

### The proxy binds loopback only

So `exec` cannot guard sibling containers — compose services, dind. Fine for the main case, worth
stating.

### `--out` is not written atomically

`os.WriteFile` straight onto the destination. A crash or a full disk mid-write leaves a truncated
policy file that verified. Write to a temp file in the same directory and rename.

### `deter-guard policy --help` exits 1

`flag.ErrHelp` falls into the parse-error branch, so asking for help is reported as a usage error.

## Housekeeping

- `report.go`: the comment "The console caps a batch at 500 items too" sits on `maxAttempts = 3`.
  It belongs on `maxWindows = 500`.
- `verify.go:20` refers to `verify_test.go`, which does not exist — the vectors live in
  `guard_test.go` and `rules_vector_test.go`.
- `main.go`: `errf` and `logf` are byte-identical. Either give them different behaviour or admit
  they are one function.
- `.dockerignore` does not exclude `.claude/`.
- CI runs `go test` without `-race`.

## Still open from the transparent-mode review

These came out of reading `serve.go`, `transparent.go`, `envcmd.go`, `installca.go`,
`redirect_*.go`, `roots.go` and `action/`. Every file listed there has now been read.

### The auto-permitted CI control plane is a broad exfil channel

`ciControlPlaneHosts()` appends rules with `PathPrefixes: ["/"]` — any method, any path — for
`github.com`, `api.github.com`, `objects.githubusercontent.com` and `*.blob.core.windows.net`. The
last is general-purpose Azure blob storage, so a malicious postinstall has a permitted write target.
The trade is sound and `--no-ci-hosts` turns it off; it belongs in the README's limits list next to
the DNS caveat, because it is the same shape of hole.

### `installca.go` has a trust store entry that can never match

The third entry (Alpine) is byte-identical to the first: same directory, same file, same refresh
command. And the "no system trust store found" error hardcodes `trustStores[0]` and `[1]`, so it
goes stale as soon as the list grows a fourth.

### `DETER_GUARD_ROOTS=system` does not fail the way its comment says

The comment is emphatic that there is no fallback — the operator asked for the host's trust
decisions specifically. But a failed `SystemCertPool()` returns a nil pool, and a nil `RootCAs` means
Go loads the platform store anyway. On Linux that is a silent fallback to roughly what was refused.

### Nothing fails when `roots.pem` ages

Currently Mozilla's set as of 13 Aug 2026, which is fresh. There is no test and no scheduled refresh,
so it rots quietly and the first symptom is a handshake failure against a newly-issued root.
