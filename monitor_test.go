package main

// Monitor mode: the same decision, not applied.
//
// The property worth testing is a comparison, not a behaviour in isolation — for one policy and one
// request, enforce refuses and monitor forwards, and both record the identical refusal. A test that
// only checked "monitor allowed it" would pass just as happily against a proxy that had stopped
// deciding anything at all, which is the failure this mode could plausibly have.

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Mode
		ok   bool
	}{
		// Unset is enforce. The other default fails silently: a job that looks guarded, reports
		// refusals, and ships the package anyway.
		{"", ModeEnforce, true},
		{"enforce", ModeEnforce, true},
		{"block", ModeEnforce, true},
		{"monitor", ModeMonitor, true},
		{"MONITOR", ModeMonitor, true},
		{"  audit ", ModeMonitor, true},
		{"dry-run", ModeMonitor, true},
		{"observe", ModeEnforce, false},
	} {
		got, err := parseMode(c.in)
		if (err == nil) != c.ok {
			t.Errorf("parseMode(%q) error = %v, want ok=%v", c.in, err, c.ok)
		}
		// A rejected mode must still leave the caller holding the SAFE one, in case anybody ever
		// decides a bad flag is only a warning.
		if got != c.want {
			t.Errorf("parseMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// testReporter is a reporter with no console behind it: note() fills the map and nothing is posted.
func testReporter() *reporter {
	return &reporter{windows: map[windowKey]*window{}, stop: make(chan struct{}), done: make(chan struct{})}
}

func blockedTarballPolicy(host string) *Policy {
	return &Policy{
		Version: 9,
		Rules:   []Rule{{Host: host}},
		Blocked: []Block{{
			Host:      host,
			PathGlobs: []string{"*/left-pad-1.3.0.tgz"},
			Reason:    "left-pad 1.3.0 is on your organization's blocklist",
		}},
	}
}

// One policy, one request, both modes. The refusal is recorded either way; only the 403 differs.
func TestMonitorForwardsWhatEnforceRefuses(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tarball:" + r.URL.Path))
	}))
	defer origin.Close()
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())
	host := mustHost(t, strings.TrimPrefix(origin.URL, "https://"))
	tarball := origin.URL + "/left-pad/-/left-pad-1.3.0.tgz"

	t.Run("enforce refuses it", func(t *testing.T) {
		client, px, stop := startProxyMode(t, blockedTarballPolicy(host), originRoot, ModeEnforce, testReporter())
		defer stop()

		code, body := get(t, client, tarball)
		if code != http.StatusForbidden {
			t.Fatalf("got %d %q, want 403", code, body)
		}
		if strings.Contains(body, "tarball:") {
			t.Error("the origin was reached anyway")
		}
		if list, _, _, _ := px.summary(); len(list) != 1 {
			t.Fatalf("want one refusal in the summary, got %d", len(list))
		}
	})

	t.Run("monitor forwards it and still records the refusal", func(t *testing.T) {
		rep := testReporter()
		client, px, stop := startProxyMode(t, blockedTarballPolicy(host), originRoot, ModeMonitor, rep)
		defer stop()

		code, body := get(t, client, tarball)
		if code != http.StatusOK {
			t.Fatalf("got %d %q, want the request to go through untouched", code, body)
		}
		if !strings.Contains(body, "tarball:/left-pad/-/left-pad-1.3.0.tgz") {
			t.Errorf("the origin's own response must be relayed verbatim, got %q", body)
		}

		// Allowing it through is only half the mode. Losing the refusal would make the run useless:
		// there would be nothing to take to the console at the end of it.
		list, _, _, _ := px.summary()
		if len(list) != 1 {
			t.Fatalf("want one recorded refusal, got %d: %+v", len(list), list)
		}
		if list[0].path != "/left-pad/-/left-pad-1.3.0.tgz" {
			t.Errorf("recorded path %q — the PATH is what the policy will have to name", list[0].path)
		}
		if !strings.Contains(list[0].reason, "blocklist") {
			t.Errorf("reason %q must still say why it would have been refused", list[0].reason)
		}
		if len(rep.windows) != 1 {
			t.Errorf("the console must be told too: %d window(s), want 1", len(rep.windows))
		}
		for k := range rep.windows {
			if k.decision != "deny_blocklist" {
				t.Errorf("decision %q — the console must see the same verdict either way", k.decision)
			}
		}
	})
}

// The reason monitor mode opens a tunnel it would have refused: refusing at CONNECT is right when
// enforcing and useless when observing, because it never learns which paths the build wanted.
func TestMonitorLearnsThePathsBehindARefusedHost(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("reached:" + r.URL.Path))
	}))
	defer origin.Close()
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())

	// Permits some other host entirely, so this one is refused at the tunnel.
	pol := &Policy{Version: 4, Rules: []Rule{{Host: "somewhere.else.example.com"}}}
	client, px, stop := startProxyMode(t, pol, originRoot, ModeMonitor, nil)
	defer stop()

	code, body := get(t, client, origin.URL+"/pkg/thing.tgz")
	if code != http.StatusOK || !strings.Contains(body, "reached:/pkg/thing.tgz") {
		t.Fatalf("monitor mode must not refuse an unpermitted host: got %d %q", code, body)
	}

	list, _, _, _ := px.summary()
	var sawConnect, sawPath bool
	for _, r := range list {
		switch {
		case r.method == "CONNECT":
			sawConnect = true
		case r.path == "/pkg/thing.tgz":
			sawPath = true
			if !strings.Contains(r.reason, "not permitted") {
				t.Errorf("reason %q", r.reason)
			}
		}
	}
	if !sawConnect {
		t.Error("the tunnel-level refusal — the host to permit — was not recorded")
	}
	if !sawPath {
		t.Errorf("the request inside the tunnel was not recorded: %+v", list)
	}
}

// Monitor mode relaxes POLICY decisions. It cannot relax a request with no destination, because
// there is nothing to forward it to — and a proxy that tried would be guessing where to send bytes
// on behalf of a build.
func TestMonitorStillRefusesWhatItCannotIdentify(t *testing.T) {
	px := newProxy(&Policy{Rules: []Rule{{Host: "ok.example.com"}}}, nil, nil, nil, ModeMonitor, false)

	for _, d := range []Decision{
		malformedHost,
		malformedPath,
		{Kind: "deny_policy", Reason: "no SNI", Malformed: true},
	} {
		if px.record(d, "whatever", "GET", "/x") {
			t.Errorf("monitor mode let an unidentifiable request proceed: %s", d.Reason)
		}
	}

	// The ordinary refusal, for contrast: this one does proceed.
	if !px.record(Decision{Kind: "deny_policy", Reason: "host not permitted"}, "h", "GET", "/x") {
		t.Error("a policy refusal must be observed, not applied, in monitor mode")
	}
}

// A retry loop is one line in the summary, not four hundred.
func TestSummaryCollapsesRetriesAndCountsAllows(t *testing.T) {
	px := newProxy(&Policy{}, nil, nil, nil, ModeEnforce, false)
	deny := Decision{Kind: "deny_policy", Reason: "host not permitted by the egress policy"}

	for i := 0; i < 3; i++ {
		px.record(deny, "bad.example.com", "GET", "/a")
	}
	px.record(deny, "bad.example.com", "GET", "/b")
	px.record(Decision{Allow: true, Kind: "allow"}, "ok.example.com", "GET", "/fine")

	list, allowed, _, dropped := px.summary()
	if len(list) != 2 {
		t.Fatalf("want two distinct targets, got %d", len(list))
	}
	if list[0].count != 3 || list[0].path != "/a" {
		t.Errorf("first entry = %+v, want /a seen 3 times, first-seen first", list[0])
	}
	if allowed != 1 {
		t.Errorf("allowed = %d, want 1 — the summary says what got through as well", allowed)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
	// Runs on both modes' summaries; the assertion is that neither panics on an empty or full tally.
	px.logSummary()
	px.mode = ModeMonitor
	px.logSummary()
}

// Transparent mode is where monitor mode is most useful — everything is intercepted, so the first
// run tells you what the machine actually talks to — and it is a different call path.
func TestTransparentMonitorForwardsARefusedHost(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("upstream reached"))
	}))
	defer origin.Close()

	pol := &Policy{Version: 2, Rules: []Rule{{Host: "permitted.example.com"}}}
	tlsAddr, _, px := transparentFixture(t, pol, origin, ModeMonitor)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(px.ca.caPEM()) {
		t.Fatal("the guard CA did not parse as PEM")
	}
	client := clientTo(t, tlsAddr, "refused.example.com", pool)

	res, err := client.Get("https://refused.example.com/pkg")
	if err != nil {
		t.Fatalf("monitor mode must forward a host it would refuse: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want the request to reach the origin", res.StatusCode)
	}
	if list, _, _, _ := px.summary(); len(list) == 0 {
		t.Error("nothing was recorded, so the run produced no reason to change the policy")
	}
}
