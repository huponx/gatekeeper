package status

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sample = `{"items":[
 {"metadata":{"name":"identity"},"status":{"sync":{"status":"Synced","revision":"abc123"},"health":{"status":"Healthy"},"operationState":{"finishedAt":"2026-11-22T10:00:00Z"}}},
 {"metadata":{"name":"gatekeeper"},"status":{"sync":{"status":"OutOfSync"},"health":{"status":"Degraded"}}},
 {"metadata":{"name":"multi"},"status":{"sync":{"status":"Synced","revisions":["r1","r2"]},"health":{"status":"Healthy"}}},
 {"metadata":{"name":"op"},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"},"operationState":{"syncResult":{"revision":"fromop"}}}},
 {"metadata":{"name":"new"},"status":{}}
]}`

func server(t *testing.T, calls *atomic.Int32, code int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/applications" || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Has("fields") {
			t.Errorf("a fields mask drops status.health in ArgoCD, it must not be sent: %q", r.URL.RawQuery)
		}
		if r.URL.Query().Get("projects") != "mm" {
			t.Errorf("projects = %q", r.URL.Query().Get("projects"))
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(sample))
	}))
}

func TestAppsSummarisesAndCaches(t *testing.T) {
	var calls atomic.Int32
	srv := server(t, &calls, 200)
	defer srv.Close()
	c, err := New(Config{URL: srv.URL + "/", Token: "tok", Project: "mm", CacheTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	apps, err := c.Apps(context.Background())
	if err != nil || len(apps) != 5 {
		t.Fatalf("apps %v err %v", apps, err)
	}
	if apps[0] != (App{Name: "identity", Sync: "Synced", Health: "Healthy", Revision: "abc123", SyncedAt: "2026-11-22T10:00:00Z"}) {
		t.Errorf("first %+v", apps[0])
	}
	if apps[1].Sync != "OutOfSync" || apps[1].Health != "Degraded" {
		t.Errorf("second %+v", apps[1])
	}
	if apps[2].Revision != "r1" || apps[3].Revision != "fromop" {
		t.Errorf("revision fallbacks: %+v %+v", apps[2], apps[3])
	}
	if apps[4].Sync != "Unknown" || apps[4].Health != "Unknown" {
		t.Errorf("empty status must be Unknown: %+v", apps[4])
	}
	if _, err := c.Apps(context.Background()); err != nil || calls.Load() != 1 {
		t.Errorf("second call must come from the cache: calls=%d err=%v", calls.Load(), err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.Apps(context.Background()); err != nil || calls.Load() != 2 {
		t.Errorf("an expired cache must call again: calls=%d err=%v", calls.Load(), err)
	}
}

func TestAppsError(t *testing.T) {
	var calls atomic.Int32
	srv := server(t, &calls, 500)
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL, Token: "tok", Project: "mm"})
	if _, err := c.Apps(context.Background()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v", err)
	}
	bad, _ := New(Config{URL: srv.URL, Token: "wrong", Project: "mm"})
	if _, err := bad.Apps(context.Background()); err == nil {
		t.Error("a refused token must fail")
	}
}

func TestNewValidates(t *testing.T) {
	for _, cfg := range []Config{{URL: "", Token: "t"}, {URL: "ftp://x", Token: "t"}, {URL: "http://x"}} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%+v must fail", cfg)
		}
	}
}
