package session

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func store(t *testing.T, keys ...string) *Store {
	t.Helper()
	addr := os.Getenv("GATEKEEPER_TEST_REDIS")
	if addr == "" {
		t.Skip("GATEKEEPER_TEST_REDIS (host:port) is not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	t.Cleanup(func() { rdb.FlushDB(context.Background()); rdb.Close() })
	if len(keys) == 0 {
		keys = []string{"k1:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))}
	}
	s, err := New(rdb, Config{Keys: keys, IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	s := store(t)
	id, err := s.Create(ctx, Session{Subject: "u1", IDPSessionID: "sid1", AccessToken: "at", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, id)
	if err != nil || got.AccessToken != "at" || got.CSRF == "" || got.Subject != "u1" {
		t.Fatalf("get: %+v %v", got, err)
	}
	// tokens are not readable in Redis
	raw, _ := s.rdb.Get(ctx, s.skey(id)).Result()
	if strings.Contains(raw, "at") && strings.Contains(raw, "rt\"") {
		t.Fatalf("stored in clear: %s", raw)
	}
	got.AccessToken = "at2"
	if err := s.Update(ctx, id, *got); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.Get(ctx, id); got.AccessToken != "at2" {
		t.Fatalf("update lost: %+v", got)
	}
	if _, err := s.Get(ctx, "short"); !errors.Is(err, ErrNotFound) {
		t.Fatal("short id accepted")
	}

	n, err := s.DeleteByIDPSession(ctx, "sid1")
	if err != nil || n != 1 {
		t.Fatalf("delete by sid: %d %v", n, err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("session survived back-channel logout")
	}
}

func TestSealBoundToSession(t *testing.T) {
	ctx := context.Background()
	s := store(t)
	a, _ := s.Create(ctx, Session{Subject: "a", AccessToken: "A"})
	b, _ := s.Create(ctx, Session{Subject: "b", AccessToken: "B"})
	// moving the sealed value of a to the key of b must not open (AAD = session id digest)
	v, _ := s.rdb.Get(ctx, s.skey(a)).Result()
	s.rdb.Set(ctx, s.skey(b), v, time.Hour)
	if _, err := s.Get(ctx, b); err == nil {
		t.Fatal("sealed value opened under another session id")
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	k1 := "k1:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	k2 := "k2:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	old := store(t, k1)
	id, _ := old.Create(ctx, Session{Subject: "u", AccessToken: "x"})
	rotated, _ := New(old.rdb, Config{Keys: []string{k2, k1}, IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour})
	if _, err := rotated.Get(ctx, id); err != nil {
		t.Fatalf("old key must still open: %v", err)
	}
	dropped, _ := New(old.rdb, Config{Keys: []string{k2}, IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour})
	if _, err := dropped.Get(ctx, id); err == nil {
		t.Fatal("session opened without its key")
	}
}

func TestLoginSingleUseAndLock(t *testing.T) {
	ctx := context.Background()
	s := store(t)
	if err := s.PutLogin(ctx, "st", Login{Nonce: "n", Verifier: "v", ReturnTo: "/x"}); err != nil {
		t.Fatal(err)
	}
	l, err := s.TakeLogin(ctx, "st")
	if err != nil || l.Nonce != "n" || l.ReturnTo != "/x" {
		t.Fatalf("take: %+v %v", l, err)
	}
	if _, err := s.TakeLogin(ctx, "st"); !errors.Is(err, ErrNotFound) {
		t.Fatal("login state is reusable")
	}
	ok1, _ := s.Lock(ctx, "id", time.Second)
	ok2, _ := s.Lock(ctx, "id", time.Second)
	if !ok1 || ok2 {
		t.Fatalf("lock: %v %v", ok1, ok2)
	}
}

func TestAbsoluteLifetime(t *testing.T) {
	ctx := context.Background()
	s := store(t)
	now := time.Now()
	s.cfg.Now = func() time.Time { return now }
	id, _ := s.Create(ctx, Session{Subject: "u"})
	now = now.Add(3 * time.Hour)
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absolute lifetime not enforced: %v", err)
	}
}
