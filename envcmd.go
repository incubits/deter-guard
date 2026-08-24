package main

// `deter-guard env`: print the variables that point a build at a running proxy.
//
// proxyEnv() knows fourteen variables across seven ecosystems, and until now that knowledge was
// reachable only by being a child of `exec`. Anyone integrating the guard any other way — a CI job
// that wants several steps guarded without a prefix on each, a Dockerfile, a devcontainer — had to
// copy the list into their own repository, where it silently stops matching the next time a variable
// is added. This is that list, as output.
//
//	eval "$(deter-guard env)"                    # this shell, and everything it starts
//	deter-guard env --format github >> "$GITHUB_ENV"
//	deter-guard env --format docker              # paste into a Dockerfile
//	eval "$(deter-guard env --unset)"            # put the shell back
//
// With no --proxy/--ca it reads the state file `serve` wrote, so the common case takes no arguments
// and cannot disagree with the running proxy.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// shQuote wraps a value in single quotes for `eval`. Paths and URLs are attacker-influenced only
// insofar as an operator chose them, but `eval` is unforgiving enough to be worth doing properly.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// splitVar splits "K=V" into its parts. proxyEnv builds these, so a missing "=" is a bug here rather
// than bad input, and the caller may treat the value as empty.
func splitVar(kv string) (string, string) {
	k, v, _ := strings.Cut(kv, "=")
	return k, v
}

// emitEnv writes the variables in one of the supported formats.
//
// Takes a writer rather than printing, so a test can assert on the exact bytes an integrator would
// paste into a Dockerfile or eval in a shell — the two places where being subtly wrong is expensive.
func emitEnv(w io.Writer, vars []string, format string, unset bool) error {
	// A newline in a value would let a crafted path forge extra entries in $GITHUB_ENV, which is a
	// step-to-step privilege boundary in Actions. Nothing we generate contains one; refuse anyway,
	// because the cost of being wrong here is somebody else's pipeline.
	for _, kv := range vars {
		if strings.ContainsAny(kv, "\n\r") {
			return errors.New("refusing to emit a value containing a newline")
		}
	}

	switch format {
	case "", "sh":
		for _, kv := range vars {
			k, v := splitVar(kv)
			if unset {
				fmt.Fprintf(w, "unset %s\n", k)
			} else {
				fmt.Fprintf(w, "export %s=%s\n", k, shQuote(v))
			}
		}

	case "github":
		for _, kv := range vars {
			if unset {
				// Actions has no unset; an empty value is how a later step sees it cleared.
				k, _ := splitVar(kv)
				fmt.Fprintf(w, "%s=\n", k)
			} else {
				fmt.Fprintln(w, kv)
			}
		}

	case "docker":
		if unset {
			return errors.New("--unset makes no sense for --format docker: an image layer can set " +
				"a build's environment, never clear one")
		}
		for _, kv := range vars {
			k, v := splitVar(kv)
			fmt.Fprintf(w, "ENV %s=%q\n", k, v)
		}

	case "json":
		// For anything scripting this that is not a shell.
		fmt.Fprintln(w, "{")
		for i, kv := range vars {
			k, v := splitVar(kv)
			comma := ","
			if i == len(vars)-1 {
				comma = ""
			}
			fmt.Fprintf(w, "  %q: %q%s\n", k, v, comma)
		}
		fmt.Fprintln(w, "}")

	default:
		return fmt.Errorf("unknown --format %q (want: sh, github, docker, json)", format)
	}
	return nil
}

func runEnvCommand(o opts) int {
	proxyURL, caPath := o.proxyURL, o.caPath

	// Fall back to whatever `serve` published. Consulting the state file only when something is
	// missing keeps an explicit --proxy from being silently half-overridden by a stale file.
	if proxyURL == "" || caPath == "" {
		stateDir := o.stateDir
		if stateDir == "" {
			stateDir = os.TempDir()
		}
		st, err := readState(stateDir)
		if err != nil {
			errf("no --proxy/--ca given and no running guard found in %s "+
				"(start one with `deter-guard serve --detach`)", stateDir)
			return exitUsage
		}
		if proxyURL == "" {
			proxyURL = st.ProxyURL
		}
		if caPath == "" {
			caPath = st.CAPath
		}
	}

	if err := emitEnv(os.Stdout, proxyEnv(proxyURL, caPath), o.format, o.unset); err != nil {
		errf("%s", err)
		return exitUsage
	}
	return exitOK
}
