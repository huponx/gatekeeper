package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gocommon/jwtx"
	"go.uber.org/zap"
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
