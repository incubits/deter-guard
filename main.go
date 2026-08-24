// deter-guard — what a CI job runs to get its organization's signed egress policy.
//
//	deter-guard whoami     what this pipeline authenticates as
//	deter-guard policy     fetch + VERIFY the signed policy, write it to a file
//	deter-guard exec       run ONE command behind the filtering proxy
//	deter-guard serve      run the proxy on its own, so many commands can sit behind it
//	deter-guard env        print the variables that point a build at a running proxy
//
// Designed to need nothing but a console URL. On GitHub Actions it mints its own OIDC token, so
// there is no secret in the pipeline to leak; elsewhere DETER_ID_TOKEN or DETER_CI_TOKEN covers it.
//
// A static binary with no dependencies, in a scratch-based image: the thing you put in front of a
// supply-chain problem shouldn't drag in a language runtime and a package tree of its own.
//
// Exit codes are distinct on purpose — a pipeline should be able to tell these apart without
// grepping stderr:
//
//	0  fine
//	1  usage or configuration problem
//	2  the policy did NOT verify        (treat as compromise until proven otherwise)
//	3  authentication or authorization failed (includes being over a plan limit)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	exitOK         = 0
	exitUsage      = 1
	exitUnverified = 2
	exitAuth       = 3
)

const defaultAudience = "deter-console"

// version is stamped at build time (-ldflags "-X main.version=…").
var version = "dev"

func errf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "deter-guard: "+format+"\n", a...)
}

// logf writes progress to stderr, so stdout stays clean for a policy or JSON the caller is piping.
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "deter-guard: "+format+"\n", a...)
}

type opts struct {
	consoleURL string
	audience   string
	pubkey     string
	outFile    string
	project    string
	run        string
	asJSON     bool
	// exec and serve
	policyFile string
	stateDir   string
	verbose    bool
	// serve only
	addr      string
	port      int
	caOut     string
	readyFile string
	detach    bool
	wrap      bool
	// env only
	format   string
	proxyURL string
	caPath   string
	unset    bool
}

const usage = `deter-guard — fetch, verify and ENFORCE this organization's signed egress policy

Usage:
  deter-guard whoami [options]
  deter-guard policy [options]
  deter-guard exec   [options] -- <command...>
  deter-guard serve  [options] [--wrap -- <command...>]
  deter-guard env    [options]

Options:
  --console <url>    Console base URL             (env DETER_CONSOLE_URL)
  --pubkey <hex>     PIN the signing key          (env DETER_POLICY_PUBKEY)
  --out <path>       Write the policy here        (default: stdout)
  --audience <aud>   OIDC audience                (env DETER_CI_OIDC_AUDIENCE, default deter-console)
  --project <ref>    Project id for a dtrc_ token (env DETER_PROJECT)
  --run <ref>        Run id, deduplicates usage   (env DETER_RUN_ID)
  --json             Machine-readable output

exec and serve options:
  --policy <path>    Use a local policy file instead of the console (UNSIGNED)
  --state-dir <dir>  Where the CA and state file go (env DETER_STATE_DIR, default: temp dir)
  --verbose          Log allowed requests too, not just refusals

serve options:
  --addr <ip>        Listen address (default 127.0.0.1; anything else is warned about)
  --port <n>         Listen port    (default 3128; 0 lets the kernel pick)
  --ca-out <path>    Write the CA here, and do not delete it on exit
  --ready-file <p>   Write the proxy URL here once it is actually listening
  --detach           Background the proxy and return once it is up
  --wrap             Run one command on a FIXED port, then shut down

env options:
  --format <fmt>     sh (default), github, docker, json
  --proxy <url>      Proxy URL   (default: read from the running guard)
  --ca <path>        CA path     (default: read from the running guard)
  --unset            Emit lines that CLEAR the variables instead of setting them

  --version          Print the version
  -h, --help         This

Credentials, in the order tried:
  1. DETER_ID_TOKEN         an OIDC ID token you pass in (GitLab and friends)
  2. GitHub Actions OIDC    automatic, needs ` + "`permissions: id-token: write`" + `
  3. DETER_CI_TOKEN         a long-lived dtrc_ token from the console

The guard's own TLS roots are embedded, so it works when copied into an image that carries no CA
store at all. DETER_GUARD_ROOTS=system|embedded|both (default both) changes that.

Exit codes: 0 ok · 1 usage · 2 policy did NOT verify · 3 auth failed`

func env(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}

// envInt is env() for a port. A value that is set but unparseable is a configuration mistake worth
// naming: silently using the default would leave the operator looking at a port they did not choose.
func envInt(k string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		errf("%s=%q is not a number — using %d", k, v, fallback)
		return fallback
	}
	return n
}

// authenticate resolves a bearer token for the CI API.
//
// Prefers the OIDC exchange, because it leaves nothing long-lived in the pipeline. A dtrc_ token is
// the fallback for platforms that can't issue an ID token.
func authenticate(ctx context.Context, o opts) (token, how, pubkey string, err error) {
	ciToken := strings.TrimSpace(os.Getenv("DETER_CI_TOKEN"))

	id, idErr := getIDToken(ctx, o.audience, osEnv)
	if idErr == nil {
		s, exErr := exchangeIDToken(ctx, o.consoleURL, id.token)
		if exErr != nil {
			// The exchange was REJECTED, not absent. Falling back here would mask a real
			// misconfiguration — wrong audience, owner not claimed — behind a different credential.
			return "", "", "", exErr
		}
		name := s.Project.Path
		if name == "" {
			name = s.Project.Ref
		}
		return s.Token, fmt.Sprintf("OIDC (%s) → %s", id.source, name), s.Pubkey, nil
	}

	if isOidcError(idErr) && ciToken != "" {
		return ciToken, "DETER_CI_TOKEN", "", nil
	}
	return "", "", "", idErr
}

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Println(usage)
		return exitUsage
	}
	cmd := os.Args[1]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Println(usage)
		return exitOK
	case "--version", "version":
		fmt.Println(version)
		return exitOK
	}
	switch cmd {
	case "whoami", "policy", "exec", "serve", "env":
	default:
		errf("unknown command %q", cmd)
		fmt.Println(usage)
		return exitUsage
	}

	// Before anything makes a TLS connection. See roots.go: the guard carries its own root store so
	// that being copied into a slim image does not silently break its own outbound TLS.
	installRoots()

	var o opts
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Println(usage) }
	fs.StringVar(&o.consoleURL, "console", env("DETER_CONSOLE_URL", ""), "")
	fs.StringVar(&o.audience, "audience", env("DETER_CI_OIDC_AUDIENCE", defaultAudience), "")
	fs.StringVar(&o.pubkey, "pubkey", env("DETER_POLICY_PUBKEY", ""), "")
	fs.StringVar(&o.outFile, "out", "", "")
	fs.StringVar(&o.project, "project", env("DETER_PROJECT", ""), "")
	fs.StringVar(&o.run, "run", env("DETER_RUN_ID", ""), "")
	fs.BoolVar(&o.asJSON, "json", false, "")
	fs.StringVar(&o.policyFile, "policy", env("DETER_POLICY_FILE", ""), "")
	fs.StringVar(&o.stateDir, "state-dir", env("DETER_STATE_DIR", ""), "")
	fs.BoolVar(&o.verbose, "verbose", false, "")
	fs.StringVar(&o.addr, "addr", env("DETER_GUARD_ADDR", "127.0.0.1"), "")
	fs.IntVar(&o.port, "port", envInt("DETER_GUARD_PORT", defaultProxyPort), "")
	fs.StringVar(&o.caOut, "ca-out", env("DETER_GUARD_CA_OUT", ""), "")
	fs.StringVar(&o.readyFile, "ready-file", "", "")
	fs.BoolVar(&o.detach, "detach", false, "")
	fs.BoolVar(&o.wrap, "wrap", false, "")
	fs.StringVar(&o.format, "format", "sh", "")
	fs.StringVar(&o.proxyURL, "proxy", "", "")
	fs.StringVar(&o.caPath, "ca", "", "")
	fs.BoolVar(&o.unset, "unset", false, "")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return exitUsage
	}

	// These three resolve their own policy (or need none), so they run before the block below that
	// insists on a console URL.
	switch cmd {
	case "exec":
		return runExecCommand(o, fs.Args())
	case "serve":
		return runServeCommand(o, fs.Args())
	case "env":
		return runEnvCommand(o)
	}

	if o.consoleURL == "" {
		errf("no console URL — pass --console or set DETER_CONSOLE_URL")
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*httpTimeout)
	defer cancel()

	token, how, sessionKey, err := authenticate(ctx, o)
	if err != nil {
		if isOidcError(err) {
			errf("%s", err)
			if !looksLikeCI(osEnv) {
				errf("(this doesn't look like a CI runner — is that intended?)")
			}
			return exitAuth
		}
		var ae *apiError
		if errors.As(err, &ae) {
			errf("authentication failed (HTTP %d): %s", ae.Status, ae.Msg)
		} else {
			errf("authentication failed: %s", err)
		}
		return exitAuth
	}

	// A dtrc_ token's project identity comes from a header, so BOTH commands send it — otherwise
	// whoami reports the token's fallback identity and disagrees with what policy attributes the
	// run to.
	headers := map[string]string{}
	if o.project != "" {
		headers["X-Deter-Project"] = o.project
	}
	if o.run != "" {
		headers["X-Deter-Run"] = o.run
	}

	if cmd == "whoami" {
		me, err := fetchWhoAmI(ctx, o.consoleURL, token, headers)
		if err != nil {
			errf("%s", err)
			var ae *apiError
			if errors.As(err, &ae) && ae.Status < 500 {
				return exitAuth
			}
			return exitUsage
		}
		if o.asJSON {
			b, _ := json.MarshalIndent(me, "", "  ")
			fmt.Println(string(b))
			return exitOK
		}
		name := me.ProjectPath
		if name == "" {
			name = me.ProjectRef
		}
		attested := "no — identity is self-reported"
		if me.Attested {
			attested = "yes"
		}
		fmt.Printf("authenticated via %s\n", how)
		fmt.Printf("  organization  %s\n", me.OrganizationID)
		fmt.Printf("  project       %s (%s)\n", name, me.Provider)
		fmt.Printf("  attested      %s\n", attested)
		return exitOK
	}

	bundle, servedKey, err := fetchPolicy(ctx, o.consoleURL, token, headers)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			errf("could not fetch the policy (HTTP %d): %s", ae.Status, ae.Msg)
			if ae.Status >= 400 && ae.Status < 500 {
				return exitAuth
			}
			return exitUsage
		}
		errf("could not fetch the policy: %s", err)
		return exitUsage
	}

	// The key we verify against decides what "verified" is worth. A PINNED key proves the policy came
	// from the holder of the fleet's private key. The key the SERVER hands us proves only that the
	// bundle is internally consistent — anything that can serve the bundle can serve a matching key.
	// Both are supported; only one is a security claim, and the guard says which.
	pinned := strings.TrimSpace(o.pubkey)
	key := pinned
	if key == "" {
		key = sessionKey
	}
	if key == "" {
		key = servedKey
	}
	if key == "" {
		errf("no public key to verify against — pass --pubkey or set DETER_POLICY_PUBKEY")
		return exitUsage
	}

	if err := verifyBundle(bundle, key); err != nil {
		errf("POLICY DID NOT VERIFY: %s", err)
		errf("key %s · version %d", keyFingerprint(key), bundle.Version)
		errf("refusing to write it. Treat this as a compromised distribution path until proven otherwise.")
		return exitUnverified
	}

	if o.outFile != "" {
		if err := os.WriteFile(o.outFile, []byte(bundle.Policy+"\n"), 0o644); err != nil {
			errf("verified, but could not write %s: %s", o.outFile, err)
			return exitUsage
		}
	}

	if o.asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"ok":      true,
			"version": bundle.Version,
			"bytes":   len(bundle.Policy),
			"key":     keyFingerprint(key),
			"pinned":  pinned != "",
			"written": o.outFile,
		}, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("policy verified · version %d · key %s\n", bundle.Version, keyFingerprint(key))
		if pinned == "" {
			errf("key was NOT pinned — this proves the bundle is self-consistent, not that it came " +
				"from you. Set DETER_POLICY_PUBKEY to make this a real check.")
		}
		if o.outFile != "" {
			fmt.Printf("written to %s\n", o.outFile)
		} else {
			fmt.Print(bundle.Policy)
		}
	}
	return exitOK
}
