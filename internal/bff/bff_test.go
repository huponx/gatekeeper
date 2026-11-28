package bff

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/jwtx"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
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
	// CallStream sends these messages (filename, size, data), then returns streamErr; afterChunk runs after each is handled.
	chunks     []chunk
	streamErr  error
	afterChunk func(i int)
}

type chunk struct {
	filename string
	size     int64
	data     string
}

func (f *fakeCaller) CallStream(_ context.Context, r routes.Route, body []byte, token string, fn func(*dynamicpb.Message) error) error {
	f.gotBody, f.gotToken = string(body), token
	md := chunkDescriptor()
	for i, c := range f.chunks {
		m := dynamicpb.NewMessage(md)
		m.Set(md.Fields().ByName("filename"), protoreflect.ValueOfString(c.filename))
		m.Set(md.Fields().ByName("size"), protoreflect.ValueOfInt64(c.size))
		m.Set(md.Fields().ByName("data"), protoreflect.ValueOfBytes([]byte(c.data)))
		if err := fn(m); err != nil {
			return err
		}
		if f.afterChunk != nil {
			f.afterChunk(i)
		}
	}
	return f.streamErr
}

// chunkDescriptor is the shape of dictionary.v1.DownloadChunk.
func chunkDescriptor() protoreflect.MessageDescriptor {
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("chunk.proto"), Package: proto.String("t"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Chunk"), Field: []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("filename"), Number: proto.Int32(10), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), Label: opt},
			{Name: proto.String("size"), Number: proto.Int32(20), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(), Label: opt},
			{Name: proto.String("data"), Number: proto.Int32(30), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(), Label: opt},
		}}},
	}, nil)
	if err != nil {
		panic(err)
	}
	return fd.Messages().ByName("Chunk")
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
	tbl, err := routes.Parse([]byte("upstreams:\n  dictionary: {target: d:9090}\nroutes:\n"+
		"  - {http: \"GET /api/dictionary/downloads/{token}\", grpc: dictionary.v1.DictionaryService/DownloadDeck, upstream: dictionary, anonymous: true, download: true}\n"), nil)
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

func TestInvalidStateRestartsLoginOnce(t *testing.T) {
	r := testServer(t)
	// no state cookie: a new sign-in starts at /auth/login
	w := do(r, http.MethodGet, "/auth/callback?state=abc&code=x", nil)
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/auth/login?return_to=") {
		t.Fatalf("first failure: %d %q", w.Code, w.Header().Get("Location"))
	}
	var retry *http.Cookie
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Name, retryCookie) {
			retry = c
		}
	}
	if retry == nil {
		t.Fatal("the restart must leave a short-lived cookie")
	}
	// it fails again with the cookie set: stop, no loop
	w = do(r, http.MethodGet, "/auth/callback?state=abc&code=x", map[string]string{"Cookie": retry.Name + "=" + retry.Value})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_state") {
		t.Fatalf("second failure: %d %s", w.Code, w.Body.String())
	}
}

func streamServer(t *testing.T, fc *fakeCaller) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	tbl, err := routes.Parse([]byte("upstreams:\n  dictionary: {target: d:9090}\nroutes:\n"+
		"  - {http: \"GET /api/dictionary/export-downloads/{token}\", grpc: dictionary.v1.DictionaryService/DownloadExportPart, upstream: dictionary, anonymous: true, download: true, stream: true}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{PublicURL: "https://api.example.com", Origins: uiOrigins, Secure: true}, nil, nil, nil, fc, fakeExch{}, tbl, zap.NewNop())
	r := gin.New()
	s.Routes(r)
	return r
}

const partURL = "/api/dictionary/export-downloads/abc123.apkg"

// A streamed part: the headers come from the first chunk (the size is the Content-Length) and every chunk is written
// as it arrives, not after the last one.
func TestStreamedDownloadWritesChunksAsTheyArrive(t *testing.T) {
	fc := &fakeCaller{chunks: []chunk{{"Mi deck (part 1).apkg", 9, "abc"}, {data: "def"}, {data: "ghi"}}}
	r := streamServer(t, fc)
	req := httptest.NewRequest(http.MethodGet, partURL, nil)
	w := httptest.NewRecorder()
	fc.afterChunk = func(i int) {
		if want := []string{"abc", "abcdef", "abcdefghi"}[i]; w.Body.String() != want {
			t.Errorf("after chunk %d the client has %q, want %q", i, w.Body.String(), want)
		}
		if !w.Flushed {
			t.Errorf("chunk %d was not flushed", i)
		}
	}
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "abcdefghi" {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if fc.gotBody != `{"token":"abc123"}` || fc.gotToken != "svc-dictionary" {
		t.Errorf("call: body %q token %q", fc.gotBody, fc.gotToken)
	}
	h := w.Header()
	if h.Get("Content-Length") != "9" || h.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment;") || !strings.Contains(h.Get("Content-Disposition"), "Mi deck (part 1).apkg") {
		t.Errorf("headers: %v", h)
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("cache control %q", h.Get("Cache-Control"))
	}
}

func TestStreamedDownloadErrorBeforeTheFirstByteIsJSON(t *testing.T) {
	fc := &fakeCaller{streamErr: status.Error(codes.NotFound, "the download link does not exist or has expired")}
	w := do(streamServer(t, fc), http.MethodGet, partURL, nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "not_found") || w.Header().Get("Content-Disposition") != "" {
		t.Errorf("status %d body %q headers %v", w.Code, w.Body.String(), w.Header())
	}
}

// After the first byte the status is gone: the connection is aborted (a panic net/http understands), never a short file
// that looks complete.
func TestStreamedDownloadBreaksTheConnectionWhenTheStreamFailsMidway(t *testing.T) {
	for name, fc := range map[string]*fakeCaller{
		"upstream error": {chunks: []chunk{{"f.apkg", 6, "abc"}}, streamErr: status.Error(codes.Internal, "disk")},
		"ends early":     {chunks: []chunk{{"f.apkg", 6, "abc"}}},
	} {
		func() {
			defer func() {
				if v := recover(); v != http.ErrAbortHandler {
					t.Errorf("%s: recovered %v, want http.ErrAbortHandler", name, v)
				}
			}()
			do(streamServer(t, fc), http.MethodGet, partURL, nil)
		}()
	}
}

func TestStreamedErrorCarriesTheReasonForTheClientToTranslate(t *testing.T) {
	fc := &fakeCaller{streamErr: apperror.FailedPrecondition("this is the last admin").WithReason("last_admin", "limit", "1")}
	w := do(streamServer(t, fc), http.MethodGet, partURL, nil)
	var body struct {
		Error struct {
			Code, Reason, Message string
			Params                map[string]string
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	e := body.Error
	if w.Code != http.StatusPreconditionFailed || e.Code != "failed_precondition" || e.Reason != "last_admin" ||
		e.Params["limit"] != "1" || e.Message != "this is the last admin" {
		t.Errorf("status %d error %+v", w.Code, e)
	}
}

func TestServerErrorsDoNotLeakTheReason(t *testing.T) {
	fc := &fakeCaller{streamErr: apperror.Internal("disk /var/x is full").WithReason("disk_full")}
	w := do(streamServer(t, fc), http.MethodGet, partURL, nil)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "disk") || strings.Contains(w.Body.String(), "reason") {
		t.Errorf("status %d body %q", w.Code, w.Body.String())
	}
}

func TestRootRedirectsToPortal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	v, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: "https://auth.example.com", Audience: "gatekeeper", Keys: jwtx.StaticKeySet{}})
	if err != nil {
		t.Fatal(err)
	}
	for portal, wantCode := range map[string]int{"https://portal.example.com": http.StatusFound, "": http.StatusNotFound} {
		s := New(Config{PublicURL: "https://api.example.com", PortalURL: portal, Origins: uiOrigins, Secure: true}, nil, v, nil, nil, nil, &routes.Table{}, zap.NewNop())
		r := gin.New()
		s.Routes(r)
		w := do(r, "GET", "/", nil)
		if w.Code != wantCode || w.Header().Get("Location") != portal {
			t.Errorf("portal %q: %d %q", portal, w.Code, w.Header().Get("Location"))
		}
	}
}

// One reply message is one `data:` line of JSON, with the zero values (unread 0 must reach the browser).
func TestSSEFrame(t *testing.T) {
	md := chunkDescriptor()
	m := dynamicpb.NewMessage(md)
	m.Set(md.Fields().ByName("filename"), protoreflect.ValueOfString("a\nb"))
	frame, err := sseFrame(m)
	if err != nil {
		t.Fatal(err)
	}
	got := string(frame)
	if !strings.HasPrefix(got, "data: {") || !strings.HasSuffix(got, "}\n\n") || strings.Count(got, "\n") != 2 {
		t.Fatalf("frame %q", got)
	}
	if !strings.Contains(got, `"size":"0"`) || !strings.Contains(got, `a\nb`) {
		t.Fatalf("frame %q", got)
	}
}
