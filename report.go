package main

// Reports refused requests to the console.
//
// Same contract as the Rust broker's reporter, because they feed the same endpoint:
//
//   - only refusals, never allows — reporting every request a build makes would turn this into
//     surveillance of the customer's own traffic, which is a different product
//   - identical refusals collapse into one window with a count, so a retry loop is one row
//   - (reporter, batch) make a retry idempotent server-side; the console hashes them into its
//     dedupe key, so re-sending a flush after a timeout stores nothing rather than doubling counts
//   - it fails open and silently: a proxy that stopped filtering because it could not REPORT would
//     be a security control with an availability-shaped off switch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// Long enough for one `npm install`'s burst against a blocked host to collapse into a single
	// window; short enough that an admin sees a developer's problem while they are still on it.
	flushInterval = 30 * time.Second
	// Past this, known targets keep counting but new ones are only tallied as dropped. A truthful
	// subset that says it is incomplete beats a complete-looking sample.
	maxWindows = 500
	// The console caps a batch at 500 items too.
	maxAttempts = 3
)

type windowKey struct {
	decision, host, method, path string
}

type window struct {
	count           int64
	firstMS, lastMS int64
}

type reporter struct {
	url     string
	token   string
	headers map[string]string
	id      string

	mu      sync.Mutex
	windows map[windowKey]*window
	dropped int64
	batch   int64

	stop chan struct{}
	done chan struct{}
}

// newReporter returns nil when reporting is not configured, which is the correct default: a client
// pointed at no console reports nothing rather than failing.
func newReporter(url, token string, headers map[string]string) *reporter {
	if url == "" {
		return nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// A duplicate id only costs idempotency across two concurrent processes, so a clock
		// fallback is a fair trade against refusing to report at all.
		buf = []byte(fmt.Sprintf("%016x", time.Now().UnixNano()))
	}
	r := &reporter{
		url:     url,
		token:   token,
		headers: headers,
		id:      hex.EncodeToString(buf)[:32],
		windows: map[windowKey]*window{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go r.loop()
	return r
}

// note records one refusal. Called from the proxy's request path, so it does no I/O.
func (r *reporter) note(decision, host, method, path string) {
	if r == nil {
		return
	}
	now := time.Now().UnixMilli()
	k := windowKey{decision, host, method, path}
	r.mu.Lock()
	defer r.mu.Unlock()
	if w, ok := r.windows[k]; ok {
		w.count++
		w.lastMS = now
		return
	}
	if len(r.windows) >= maxWindows {
		r.dropped++
		return
	}
	r.windows[k] = &window{count: 1, firstMS: now, lastMS: now}
}

func (r *reporter) loop() {
	defer close(r.done)
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			r.flush()
		case <-r.stop:
			// The refusals from just before a build ends are exactly the ones worth having.
			r.flush()
			return
		}
	}
}

// Close flushes and stops. Safe to call once; the proxy calls it when the child process exits.
func (r *reporter) Close() {
	if r == nil {
		return
	}
	close(r.stop)
	select {
	case <-r.done:
	case <-time.After(20 * time.Second):
		// Never hold a build open waiting on telemetry.
	}
}

type reportItem struct {
	Decision  string `json:"decision"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Count     int64  `json:"count"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

func (r *reporter) flush() {
	r.mu.Lock()
	if len(r.windows) == 0 {
		r.mu.Unlock()
		return
	}
	r.batch++
	batch := r.batch
	dropped := r.dropped
	items := make([]reportItem, 0, len(r.windows))
	for k, w := range r.windows {
		items = append(items, reportItem{
			Decision: k.decision, Host: k.host, Method: k.method, Path: k.path,
			Count: w.count, FirstSeen: w.firstMS, LastSeen: w.lastMS,
		})
	}
	// Cleared before the POST, not after. Holding a failed batch to retry forever is how a reporter
	// becomes the memory leak that takes down what it was protecting.
	r.windows = map[windowKey]*window{}
	r.dropped = 0
	r.mu.Unlock()

	body, err := json.Marshal(map[string]any{
		"reporter": r.id, "batch": batch, "items": items, "dropped": dropped,
	})
	if err != nil {
		return
	}
	r.post(body, len(items), dropped)
}

func (r *reporter) post(body []byte, n int, dropped int64) {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if r.token != "" {
			req.Header.Set("Authorization", "Bearer "+r.token)
		}
		for k, v := range r.headers {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		cancel()

		if err == nil {
			status := res.StatusCode
			res.Body.Close()
			if status >= 200 && status < 300 {
				if dropped > 0 {
					logf("reported %d blocked target(s); %d more dropped over the %d-window cap",
						n, dropped, maxWindows)
				}
				return
			}
			// 4xx is our fault (revoked credential, malformed body) and will not fix itself.
			if status >= 400 && status < 500 {
				logf("attempt report rejected (HTTP %d) — not retrying", status)
				return
			}
			logf("attempt report failed (HTTP %d), try %d/%d", status, attempt, maxAttempts)
		} else {
			logf("attempt report failed (%s), try %d/%d", err, attempt, maxAttempts)
		}
		if attempt < maxAttempts {
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
	}
	logf("giving up on %d blocked-target report(s); filtering is unaffected", n)
}
