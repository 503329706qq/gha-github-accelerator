package control_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/control"
)

func newHandler(t *testing.T, token string) (http.Handler, *struct {
	quits   atomic.Int32
	reloads atomic.Int32
}) {
	t.Helper()
	stats := &struct {
		quits   atomic.Int32
		reloads atomic.Int32
	}{}
	h := control.New(control.Options{
		Token: token,
		CRL:   func() ([]byte, error) { return []byte("CRL-BYTES"), nil },
		Status: func() any {
			return map[string]any{"version": "0.9.9", "hosts": true}
		},
		OnQuit: func() { stats.quits.Add(1) },
		OnReload: func() error {
			stats.reloads.Add(1)
			return nil
		},
	})
	return h, stats
}

func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("X-Gha-Token", token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStatusRequiresToken(t *testing.T) {
	h, _ := newHandler(t, "s3cret")

	if rec := do(t, h, "GET", "/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: status=%d", rec.Code)
	}
	if rec := do(t, h, "GET", "/status", "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status=%d", rec.Code)
	}

	rec := do(t, h, "GET", "/status", "s3cret")
	if rec.Code != http.StatusOK {
		t.Fatalf("right token: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("bad json: %v (%s)", err, rec.Body.String())
	}
	if payload["version"] != "0.9.9" {
		t.Fatalf("payload=%v", payload)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type=%q", ct)
	}
}

func TestCRLNoAuth(t *testing.T) {
	h, _ := newHandler(t, "s3cret")
	rec := do(t, h, "GET", "/ca.crl", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Fatalf("content-type=%q", ct)
	}
	if got := rec.Body.String(); got != "CRL-BYTES" {
		t.Fatalf("body=%q", got)
	}
}

func TestQuitCallsCallback(t *testing.T) {
	h, stats := newHandler(t, "s3cret")

	if rec := do(t, h, "POST", "/quit", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized quit: status=%d", rec.Code)
	}
	if n := stats.quits.Load(); n != 0 {
		t.Fatalf("quit callback fired without token")
	}

	rec := do(t, h, "POST", "/quit", "s3cret")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d", rec.Code)
	}
	if n := stats.quits.Load(); n != 1 {
		t.Fatalf("quit callback fired %d times", n)
	}

	// GET /quit 不应触发（只接受 POST）
	if rec := do(t, h, "GET", "/quit", "s3cret"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /quit: status=%d", rec.Code)
	}
	if n := stats.quits.Load(); n != 1 {
		t.Fatalf("GET /quit fired the callback")
	}
}

func TestReloadRequiresToken(t *testing.T) {
	h, stats := newHandler(t, "s3cret")
	if rec := do(t, h, "POST", "/reload", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	rec := do(t, h, "POST", "/reload", "s3cret")
	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status=%d body=%s", rec.Code, body)
	}
	if n := stats.reloads.Load(); n != 1 {
		t.Fatalf("reload fired %d times", n)
	}
}
