package main

// Monitor or enforce: what a refusal DOES.
//
// The decision itself is identical either way — same rules, same blocklist, same proxy, same
// reporting. Only the consequence differs:
//
//	enforce   the request is refused with a 403 and never reaches the origin   (the default)
//	monitor   the request is allowed through, and the refusal that WOULD have happened is logged,
//	          reported to the console, and summarised at the end of the run
//
// This exists because of how an egress policy actually gets adopted. The first pipeline anyone wants
// one on is a pipeline they cannot afford to break, and nobody knows the full set of hosts their
// build touches — transitive installs, a vendored toolchain, one telemetry endpoint somebody added
// in 2019. Turning enforcement on blind means a red build, an urgent revert, and a control that is
// now switched off; a policy nobody dares enable protects nothing. Monitor mode is the run that
// produces the list: the same decisions, written down instead of applied.
//
// Which is why it is the same code path and not a simulator. A dry run that re-implemented the
// decision would eventually disagree with the one that enforces, and the disagreement would only
// ever be discovered in the direction of a broken build. Here the policy is consulted, the refusal
// is built, and the only branch is whether the 403 is written or the request is let through.
//
// The one thing monitor mode does NOT relax is a request the guard could not identify — a malformed
// authority, an undecodable path, a TLS connection with no SNI. There is no host to forward those
// to, so "let it through" is not an option that exists; see Decision.Malformed.

import (
	"fmt"
	"strings"
)

// Mode is what happens to a request the policy refused.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeMonitor Mode = "monitor"
)

// parseMode reads --mode. An unset value is enforce, deliberately: a guard whose mode nobody stated
// has to be the one that actually stops things. The other default fails silently — a job that looks
// guarded, reports refusals, and ships the package anyway.
func parseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "enforce", "block":
		return ModeEnforce, nil
	case "monitor", "audit", "dry-run":
		return ModeMonitor, nil
	}
	return ModeEnforce, fmt.Errorf(
		"unknown mode %q — use `monitor` (report what would be refused) or `enforce` (refuse it)", s)
}

const (
	// Distinct targets kept for the end-of-run summary. The same ceiling as the reporter's, for the
	// same reason: a build that produces more than this has a problem the first five hundred already
	// describe.
	maxSummaryTargets = 500
	// How many of them are actually printed. The rest are counted, not listed — four hundred lines
	// at the end of a build log is the same as none.
	maxSummaryLines = 20
)

// refusalKey is what makes two refusals "the same thing" for the summary. Deliberately not the
// reason: one host refused for one reason is one line, however many times a retry loop asked.
type refusalKey struct{ host, method, path string }

type refusal struct {
	refusalKey
	reason string
	count  int64
}

// tally records one refusal for the end-of-run summary.
//
// Separate from the reporter, which sends the same events to the console, because the audiences are
// different and so is the deadline. The console wants every refusal, batched, for an admin to read
// tomorrow. The developer whose build just did something unexpected wants the list now, in the log
// they are already looking at, without an account on anything.
func (p *proxy) tally(d Decision, host, method, path string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d.Allow {
		p.allowed++
		return
	}
	// A finding the ORGANIZATION set to report rather than block, in a run that is otherwise
	// enforcing. Counted apart from the rest so the end-of-run summary cannot imply that everything
	// it lists was stopped — see logSummary.
	if d.Observe && p.mode != ModeMonitor {
		p.observed++
	}
	k := refusalKey{host, method, path}
	if r, ok := p.refusals[k]; ok {
		r.count++
		return
	}
	if len(p.refusals) >= maxSummaryTargets {
		p.summaryDropped++
		return
	}
	p.refusals[k] = &refusal{refusalKey: k, reason: d.Reason, count: 1}
	p.order = append(p.order, k)
}

// summary returns the refusals in the order they were first seen, plus how many were allowed.
//
// First-seen order rather than sorted by count: the first thing a build was refused is usually the
// one that caused everything after it, and a frequency sort buries it under the retries.
func (p *proxy) summary() (list []refusal, allowed, observed, dropped int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range p.order {
		list = append(list, *p.refusals[k])
	}
	return list, p.allowed, p.observed, p.summaryDropped
}

// logSummary prints what the policy did over the whole run, once, at the end.
//
// The per-request lines are interleaved with tens of thousands of lines of build output, so on their
// own they are evidence rather than an answer. This is the answer: the list to go and permit, or the
// confirmation that there is nothing to permit and the policy is ready to enforce.
func (p *proxy) logSummary() {
	list, allowed, observed, dropped := p.summary()

	var total int64
	for _, r := range list {
		total += r.count
	}

	if len(list) == 0 {
		if p.mode == ModeMonitor && allowed > 0 {
			// The whole reason someone ran monitor mode, answered.
			logf("monitor mode: %d request(s), none of them refused — this policy is ready to "+
				"enforce for this build", allowed)
		}
		return
	}

	if p.mode == ModeMonitor {
		logf("MONITOR MODE SUMMARY: %d request(s) across %d target(s) WOULD have been refused "+
			"(%d allowed by the policy). Nothing was blocked:", total, len(list), allowed)
	} else {
		logf("%d request(s) across %d target(s) were refused (%d allowed by the policy):",
			total, len(list), allowed)
	}

	for i, r := range list {
		if i == maxSummaryLines {
			logf("  … and %d more distinct target(s), not listed", len(list)-maxSummaryLines)
			break
		}
		logf("  %6d × %s %s%s — %s", r.count, r.method, r.host, r.path, r.reason)
	}
	if dropped > 0 {
		logf("  (%d further distinct target(s) went uncounted past the %d-target cap)",
			dropped, maxSummaryTargets)
	}
	if observed > 0 && p.mode != ModeMonitor {
		// An enforcing run that nevertheless let some of these through, because the organization put
		// that class of finding on `monitor` — or because the advisory has no fixed version yet, and
		// blocking a package with nowhere to upgrade to is how a control gets switched off wholesale.
		// A summary that counted those as stopped would be reporting protection that did not happen.
		logf("  (%d of those were REPORTED ONLY and did install — your organization has that class "+
			"of finding on monitor, or the advisory has no fix yet)", observed)
	}

	if p.mode == ModeMonitor {
		logf("permit whatever belongs in your egress policy, then run with --mode enforce to make " +
			"this real. Until then this job is NOT protected.")
	}
}
