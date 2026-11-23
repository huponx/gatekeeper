package bff

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gocommon/jwtx"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var uiOrigins = []string{"https://dict.example.com", "https://bill.example.com"}

func testServer(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	v, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: "https://auth.example.com", Audience: "gatekeeper", Keys: jwtx.StaticKeySet{}})
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{PublicURL: "https://api.example.com", Origins: uiOrigins, Secure: true}, nil, v, nil, nil, nil, &routes.Table{}, zap.NewNop())
	r := gin.New()
	s.Routes(r)
	return r
}

func do(r *gin.Engine, method, path string, h map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestSafeReturn(t *testing.T) {
	cases := map[string]string{
		"":                                    "/def",
		"/app":                                "/app",
		"//evil.example":                      "/def",
		"https://dict.example.com/home?x=1":   "https://dict.example.com/home?x=1",
		"https://bill.example.com":            "https://bill.example.com",
		"https://evil.example/":               "/def",
		"https://dict.example.com.evil.io/":   "/def",
		"http://dict.example.com/":            "/def",
		"https://user@dict.example.com/":      "/def",
		"https://dict.example.com/\r\nX: y":   "/def",
		"javascript:alert(1)":                 "/def",
		"https://dict.example.com\\@evil.com": "/def",
	}
	for in, want := range cases {
		if got := safeReturn(in, "/def", uiOrigins); got != want {
			t.Errorf("safeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCORS(t *testing.T) {
	r := testServer(t)

	w := do(r, http.MethodGet, "/auth/me", map[string]string{"Origin": "https://dict.example.com"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://dict.example.com" || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("allowed origin got no CORS headers: %v", w.Header())
	}

	w = do(r, http.MethodGet, "/auth/me", map[string]string{"Origin": "https://evil.example"})
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign origin got CORS headers: %v", w.Header())
	}

	w = do(r, http.MethodOptions, "/api/anything", map[string]string{
		"Origin": "https://bill.example.com", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "csrf-token",
	})
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "https://bill.example.com" {
		t.Errorf("preflight: %d %v", w.Code, w.Header())
	}
	if h := w.Header().Get("Access-Control-Allow-Headers"); h == "" || w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Errorf("preflight lacks allow headers: %v", w.Header())
	}

	w = do(r, http.MethodOptions, "/api/anything", map[string]string{"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
	if w.Code == http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign preflight accepted: %d %v", w.Code, w.Header())
	}
}

func TestBearerRejected(t *testing.T) {
	r := testServer(t)
	for name, h := range map[string]string{
		"empty":      "Bearer ",
		"garbage":    "Bearer not.a.jwt",
		"basic":      "Basic Zm9vOmJhcg==",
		"no scheme":  "abc",
		"lower case": "bearer x.y.z",
	} {
		w := do(r, http.MethodGet, "/auth/me", map[string]string{"Authorization": h})
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, w.Code)
		}
	}
}

func TestProfileClaims(t *testing.T) {
	tok := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}
	name, email := profileClaims(tok(`{"sub":"u1","name":"Administrator","email":"admin@example.com"}`))
	if name != "Administrator" || email != "admin@example.com" {
		t.Errorf("got %q %q", name, email)
	}
	for _, bad := range []string{"", "abc", "a.b.c", tok(`not json`), tok(`{"sub":"u1"}`)} {
		if n, e := profileClaims(bad); n != "" || e != "" {
			t.Errorf("%q: got %q %q, want empty", bad, n, e)
		}
	}
}

func TestSystemStatusNeedsSignIn(t *testing.T) {
	r := testServer(t)
	if w := do(r, http.MethodGet, "/api/system/status", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d, want 401", w.Code)
	}
	if w := do(r, http.MethodGet, "/api/system/status", map[string]string{"Authorization": "Bearer not.a.jwt"}); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", w.Code)
	}
}

type fakeCaller struct {
	gotBody  string
	gotToken string
	reply    string
	err      error
}

func (f *fakeCaller) Call(_ context.Context, _ routes.Route, body []byte, token string) ([]byte, error) {
	f.gotBody, f.gotToken = string(body), token
	return []byte(f.reply), f.err
}

type fakeExch struct{}

func (fakeExch) ExchangeToken(context.Context, string, string, ...string) (string, error) {
	return "", errors.New("an anonymous route must not exchange a user token")
}
func (fakeExch) ServiceToken(_ context.Context, aud string) (string, error) { return "svc-" + aud, nil }

// The anonymous download needs no session: it calls the upstream with the service token, drops the
// extension of the link and answers with the file.
func TestAnonymousDownload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tbl, err := routes.Parse([]byte("upstreams:\n  dictionary: {target: d:9090}\nroutes:\n" +
		"  - {http: \"GET /api/dictionary/downloads/{token}\", grpc: dictionary.v1.DictionaryService/DownloadDeck, upstream: dictionary, anonymous: true, download: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeCaller{reply: `{"filename":"Mi deck.apkg","data":"` + base64.StdEncoding.EncodeToString([]byte("PK\x03\x04")) + `"}`}
	s := New(Config{PublicURL: "https://api.example.com", Origins: uiOrigins, Secure: true}, nil, nil, nil, fc, fakeExch{}, tbl, zap.NewNop())
	r := gin.New()
	s.Routes(r)

	w := do(r, http.MethodGet, "/api/dictionary/downloads/abc123.apkg", nil)
	if w.Code != http.StatusOK || w.Body.String() != "PK\x03\x04" {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if fc.gotBody != `{"token":"abc123"}` || fc.gotToken != "svc-dictionary" {
		t.Errorf("call: body %q token %q", fc.gotBody, fc.gotToken)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content type %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, "Mi deck.apkg") {
		t.Errorf("content disposition %q", cd)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("cache control %q", w.Header().Get("Cache-Control"))
	}

	// the upstream says the link is gone
	fc.err = status.Error(codes.NotFound, "the download link does not exist or has expired")
	if w := do(r, http.MethodGet, "/api/dictionary/downloads/abc123.apkg", nil); w.Code != http.StatusNotFound {
		t.Errorf("unknown link: %d %s", w.Code, w.Body.String())
	}
}
