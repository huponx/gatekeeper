// Package session keeps the BFF sessions: the browser holds an opaque random cookie, Redis holds
// the tokens, sealed with AES-GCM so that a Redis dump alone gives no token.
package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrNotFound = errors.New("session: not found")

// Session is the server side state of one browser session.
type Session struct {
	Subject      string    `json:"sub"`
	IDPSessionID string    `json:"sid"` // sid of identity, for back-channel logout
	AccessToken  string    `json:"at"`
	RefreshToken string    `json:"rt,omitempty"`
	IDToken      string    `json:"it,omitempty"`
	ExpiresAt    time.Time `json:"exp"` // of the access token
	CSRF         string    `json:"csrf"`
	CreatedAt    time.Time `json:"created"`
}

type Config struct {
	Keys        []string // "id:base64key", first seals
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	Now         func() time.Time
}

type Store struct {
	rdb  redis.UniversalClient
	cfg  Config
	keys []key
}

type key struct {
	id string
	g  cipher.AEAD
}

// New builds a store over an existing Redis client.
func New(rdb redis.UniversalClient, cfg Config) (*Store, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if len(cfg.Keys) == 0 {
		return nil, errors.New("session: at least one key is required")
	}
	s := &Store{rdb: rdb, cfg: cfg}
	for _, spec := range cfg.Keys {
		id, b64, ok := strings.Cut(spec, ":")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if !ok || id == "" || err != nil || len(raw) != 32 {
			return nil, errors.New("session: key must be \"id:base64(32 bytes)\"")
		}
		blk, _ := aes.NewCipher(raw)
		g, _ := cipher.NewGCM(blk)
		s.keys = append(s.keys, key{id: id, g: g})
	}
	return s, nil
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a fresh opaque session id.
func NewID() string { return random(32) }

// Random returns n random bytes, base64url encoded (state, nonce, verifier).
func Random(n int) string { return random(n) }

func digest(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (s *Store) skey(id string) string { return "gk:sess:" + digest(id) }

func (s *Store) seal(aad string, v any) (string, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	k := s.keys[0]
	nonce := make([]byte, k.g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := k.g.Seal(nil, nonce, pt, []byte(aad))
	return k.id + "." + base64.RawURLEncoding.EncodeToString(append(nonce, ct...)), nil
}

func (s *Store) open(aad, sealed string, v any) error {
	id, enc, ok := strings.Cut(sealed, ".")
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if !ok || err != nil {
		return errors.New("session: malformed value")
	}
	for _, k := range s.keys {
		if k.id != id || len(raw) < k.g.NonceSize() {
			continue
		}
		pt, err := k.g.Open(nil, raw[:k.g.NonceSize()], raw[k.g.NonceSize():], []byte(aad))
		if err != nil {
			return errors.New("session: cannot open value")
		}
		return json.Unmarshal(pt, v)
	}
	return errors.New("session: unknown key")
}

// Create stores a new session and returns its cookie value.
func (s *Store) Create(ctx context.Context, sess Session) (string, error) {
	id := NewID()
	sess.CSRF = random(24)
	sess.CreatedAt = s.cfg.Now()
	if err := s.put(ctx, id, sess, s.cfg.IdleTTL); err != nil {
		return "", err
	}
	pipe := s.rdb.Pipeline()
	if sess.IDPSessionID != "" { // index for back-channel logout
		pipe.SAdd(ctx, "gk:sid:"+sess.IDPSessionID, digest(id))
		pipe.Expire(ctx, "gk:sid:"+sess.IDPSessionID, s.cfg.AbsoluteTTL)
	}
	pipe.SAdd(ctx, "gk:sub:"+sess.Subject, digest(id))
	pipe.Expire(ctx, "gk:sub:"+sess.Subject, s.cfg.AbsoluteTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) put(ctx context.Context, id string, sess Session, ttl time.Duration) error {
	sealed, err := s.seal(digest(id), sess)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.skey(id), sealed, ttl).Err()
}

// Get loads a session and slides its idle timeout (never beyond the absolute lifetime).
func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	if len(id) < 32 || len(id) > 128 {
		return nil, ErrNotFound
	}
	v, err := s.rdb.Get(ctx, s.skey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sess Session
	if err := s.open(digest(id), v, &sess); err != nil {
		return nil, err
	}
	left := sess.CreatedAt.Add(s.cfg.AbsoluteTTL).Sub(s.cfg.Now())
	if left <= 0 {
		_ = s.Delete(ctx, id)
		return nil, ErrNotFound
	}
	_ = s.rdb.Expire(ctx, s.skey(id), min(s.cfg.IdleTTL, left)).Err()
	return &sess, nil
}

// Update replaces the tokens of a session (after a refresh) keeping its remaining lifetime.
func (s *Store) Update(ctx context.Context, id string, sess Session) error {
	ttl, err := s.rdb.TTL(ctx, s.skey(id)).Result()
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrNotFound
	}
	return s.put(ctx, id, sess, ttl)
}

// Delete removes one session.
func (s *Store) Delete(ctx context.Context, id string) error {
	return s.rdb.Del(ctx, s.skey(id)).Err()
}

// DeleteByIDPSession removes the sessions created from the identity session sid;
// DeleteBySubject removes every session of the user (back-channel logout without sid).
// They return how many sessions were listed.
func (s *Store) DeleteByIDPSession(ctx context.Context, sid string) (int, error) {
	return s.deleteSet(ctx, "gk:sid:"+sid)
}

func (s *Store) DeleteBySubject(ctx context.Context, sub string) (int, error) {
	return s.deleteSet(ctx, "gk:sub:"+sub)
}

func (s *Store) deleteSet(ctx context.Context, setKey string) (int, error) {
	members, err := s.rdb.SMembers(ctx, setKey).Result()
	if err != nil {
		return 0, err
	}
	for _, m := range members {
		if err := s.rdb.Del(ctx, "gk:sess:"+m).Err(); err != nil {
			return 0, err
		}
	}
	return len(members), s.rdb.Del(ctx, setKey).Err()
}

// Lock lets one replica refresh the tokens of a session: with refresh token rotation, two
// replicas refreshing with the same token would trigger reuse detection and revoke the family.
// It returns false when someone else holds the lock.
func (s *Store) Lock(ctx context.Context, id string, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, "gk:lock:"+digest(id), "1", ttl).Result()
}

func (s *Store) Unlock(ctx context.Context, id string) { s.rdb.Del(ctx, "gk:lock:"+digest(id)) }

// Login is what the callback needs from the authorization request, bound to the browser by state.
type Login struct {
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
}

// PutLogin stores the state of an authorization request for ten minutes.
func (s *Store) PutLogin(ctx context.Context, state string, l Login) error {
	sealed, err := s.seal("login:"+state, l)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, "gk:login:"+digest(state), sealed, 10*time.Minute).Err()
}

// TakeLogin returns and removes the login state (single use).
func (s *Store) TakeLogin(ctx context.Context, state string) (*Login, error) {
	v, err := s.rdb.GetDel(ctx, "gk:login:"+digest(state)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var l Login
	if err := s.open("login:"+state, v, &l); err != nil {
		return nil, fmt.Errorf("login state: %w", err)
	}
	return &l, nil
}

// CSRFEqual compares the CSRF token of a session with the one sent by the browser.
func CSRFEqual(sess *Session, got string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(got)) == 1
}
