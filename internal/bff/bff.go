// Package bff is the HTTP face of gatekeeper: the OIDC login of the web apps (the browser never
// sees a token, only an HttpOnly session cookie) and the JSON to gRPC routes that use the
// session. Every call to an upstream carries a token exchanged for that upstream's audience.
package bff

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gatekeeper/internal/proxy"
	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gatekeeper/internal/session"
	systemstatus "github.com/huponx/gatekeeper/internal/status"
	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/httpx"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/oidcclient"
	"github.com/huponx/gocommon/tokenexchange"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/dynamicpb"
)

const (
	sessionCookie = "session"
	stateCookie   = "login-state"
	retryCookie   = "login-retry"
	csrfHeader    = "Csrf-Token"
	maxBody       = 1 << 20
)

// Exchanger obtains the token sent to an upstream (satisfied by *tokenexchange.Client).
type Exchanger interface {
	ExchangeToken(ctx context.Context, subjectToken, audience string, scopes ...string) (string, error)
	// ServiceToken is a token of gatekeeper itself (client credentials), for the anonymous routes.
	ServiceToken(ctx context.Context, audience string) (string, error)
}

type Caller interface {
	Call(ctx context.Context, r routes.Route, body []byte, token string) ([]byte, error)
	// CallStream calls a server-streaming route and hands every reply message to fn (a route with stream: true).
	CallStream(ctx context.Context, r routes.Route, body []byte, token string, fn func(*dynamicpb.Message) error) error
}

// StatusSource lists the applications of the system (satisfied by *status.Client).
type StatusSource interface {
	Apps(ctx context.Context) ([]systemstatus.App, error)
}

// StatusPermission is what GET /api/system/status needs. It is declared in protos/system/v1/permissions.proto and
// TestStatusPermissionIsDeclared fails when the two differ.
const StatusPermission = "system:status:read"

type Config struct {
	PublicURL    string
	Origins      []string
	PostLoginURL string
	// PortalURL, when set, is where GET / redirects and the post login fallback (instead of "/"). Empty: GET / is a 404.
	PortalURL string
	ACRValues string
	// Secure sets the Secure flag and the __Host- prefix of the cookies (everything except ENV=local over http).
	Secure bool
}

type Server struct {
	cfg      Config
	oidc     *oidcclient.Client
	verifier *jwtx.Verifier
	sessions *session.Store
	caller   Caller
	exch     Exchanger
	table    *routes.Table
	status   StatusSource
	log      *zap.Logger
	now      func() time.Time
}

func New(cfg Config, oc *oidcclient.Client, v *jwtx.Verifier, st *session.Store, c Caller, ex Exchanger, t *routes.Table, log *zap.Logger) *Server {
	if cfg.PostLoginURL == "" || cfg.PostLoginURL == "/" {
		cfg.PostLoginURL = "/"
		if cfg.PortalURL != "" {
			cfg.PostLoginURL = cfg.PortalURL
		}
	}
	return &Server{cfg: cfg, oidc: oc, verifier: v, sessions: st, caller: c, exch: ex, table: t, log: log, now: time.Now}
}

// SetStatus enables GET /api/system/status; without it the route answers 404 not_configured.
func (s *Server) SetStatus(src StatusSource) { s.status = src }

// Routes registers /auth/* and the configured routes.
func (s *Server) Routes(r *gin.Engine) {
	r.Use(func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Cache-Control", "no-store")
		c.Next()
	})
	r.Use(s.cors)
	if s.cfg.PortalURL != "" {
		r.GET("/", func(c *gin.Context) { c.Redirect(http.StatusFound, s.cfg.PortalURL) })
	}
	r.GET("/auth/login", s.login)
	r.GET("/auth/callback", s.callback)
	r.GET("/auth/me", s.me)
	r.POST("/auth/logout", s.logout)
	r.POST("/auth/backchannel-logout", s.backchannelLogout)
	r.GET("/api/system/status", s.systemStatus)
	for _, rt := range s.table.Routes {
		r.Handle(rt.Method, ginPath(rt.Path), s.route(rt))
	}
}

// ginPath turns /users/{id} into /users/:id.
func ginPath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			parts[i] = ":" + seg[1:len(seg)-1]
		}
	}
	return strings.Join(parts, "/")
}

func (s *Server) cookieName(n string) string {
	if s.cfg.Secure {
		return "__Host-" + n
	}
	return n
}

func (s *Server) setCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: s.cookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.cfg.Secure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(c *gin.Context, name string) { s.setCookie(c, name, "", -1) }

func (s *Server) cookie(c *gin.Context, name string) string {
	v, err := c.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return v
}

// failure is an optional stable reason (and its parameters) of an error, for the client to translate.
type failure struct {
	reason string
	params map[string]string
}

func fail(c *gin.Context, status int, code, msg string, f ...failure) {
	e := gin.H{"code": code, "message": msg}
	if len(f) > 0 && f[0].reason != "" {
		e["reason"] = f[0].reason
		if len(f[0].params) > 0 {
			e["params"] = f[0].params
		}
	}
	c.AbortWithStatusJSON(status, gin.H{"error": e})
}

// cors answers the browsers of the configured UI origins (credentials allowed, so never "*").
// An unknown origin gets no CORS headers: the browser blocks the response. Preflights are
// answered here, before authentication.
func (s *Server) cors(c *gin.Context) {
	origin := c.GetHeader("Origin")
	if origin == "" {
		return
	}
	c.Writer.Header().Add("Vary", "Origin")
	if !slices.Contains(s.cfg.Origins, origin) {
		return
	}
	h := c.Writer.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	if c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Method") != "" {
		h.Add("Vary", "Access-Control-Request-Method")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
		h.Set("Access-Control-Allow-Headers", "Content-Type, "+csrfHeader+", Authorization")
		h.Set("Access-Control-Max-Age", "600")
		c.AbortWithStatus(http.StatusNoContent)
	}
}

// safeReturn accepts a path of this site, or an absolute URL on one of the UI origins.
func safeReturn(p, def string, origins []string) string {
	if p == "" || strings.ContainsAny(p, "\\\r\n") {
		return def
	}
	if p[0] == '/' {
		if strings.HasPrefix(p, "//") {
			return def
		}
		return p
	}
	u, err := url.Parse(p)
	if err != nil || u.User != nil || u.Host == "" || !slices.Contains(origins, u.Scheme+"://"+u.Host) {
		return def
	}
	return p
}

// isBearer reports whether the request authenticates with an Authorization: Bearer token
// (mobile apps and services) instead of the session cookie.
// Any Authorization header selects this mode: a malformed one is a 401, never a fallback to the cookie.
func isBearer(c *gin.Context) bool { return c.GetHeader("Authorization") != "" }

func bearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// ---- login ----

// stateCookieName gives every sign-in attempt its own cookie, so parallel attempts
// (several tabs or apps, a double click) do not overwrite each other.
func stateCookieName(state string) string {
	h := sha256.Sum256([]byte(state))
	return stateCookie + "-" + hex.EncodeToString(h[:4])
}

func (s *Server) login(c *gin.Context) {
	ctx := c.Request.Context()
	u, req, err := s.oidc.AuthURL(oidcclient.AuthURLOptions{ACRValues: s.cfg.ACRValues})
	if err != nil {
		s.log.Error("auth url", zap.Error(err))
		fail(c, http.StatusBadGateway, "unavailable", "sign-in is unavailable")
		return
	}
	ret := safeReturn(c.Query("return_to"), s.cfg.PostLoginURL, s.cfg.Origins)
	if err := s.sessions.PutLogin(ctx, req.State, session.Login{Nonce: req.Nonce, Verifier: req.Verifier, ReturnTo: ret}); err != nil {
		s.log.Error("store login state", zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "unavailable", "sign-in is unavailable")
		return
	}
	s.setCookie(c, stateCookieName(req.State), req.State, 600)
	c.Redirect(http.StatusFound, u)
}

// restartLogin answers an invalid_state of the callback (an old link, the Back button, an expired or foreign
// state): it starts a new sign-in at /auth/login, which goes back to the post login page (the return_to of the
// lost attempt is gone with its state). One restart per minute: a short-lived cookie stops a loop, and the
// second failure is the plain 400 invalid_state.
func (s *Server) restartLogin(c *gin.Context, msg string) {
	if s.cookie(c, retryCookie) != "" {
		s.clearCookie(c, retryCookie)
		fail(c, http.StatusBadRequest, "invalid_state", msg)
		return
	}
	s.setCookie(c, retryCookie, "1", 60)
	c.Redirect(http.StatusFound, "/auth/login?return_to="+url.QueryEscape(s.cfg.PostLoginURL))
}

func (s *Server) callback(c *gin.Context) {
	ctx := c.Request.Context()
	state := c.Query("state")
	if state == "" || state != s.cookie(c, stateCookieName(state)) {
		s.restartLogin(c, "the sign-in request does not belong to this browser")
		return
	}
	s.clearCookie(c, stateCookieName(state))
	if e := c.Query("error"); e != "" {
		s.log.Info("login refused by identity", zap.String("error", e))
		fail(c, http.StatusUnauthorized, "login_failed", "sign-in was not completed")
		return
	}
	l, err := s.sessions.TakeLogin(ctx, state)
	if err != nil {
		s.restartLogin(c, "the sign-in request expired")
		return
	}
	t, err := s.oidc.Exchange(ctx, c.Query("code"), oidcclient.AuthRequest{State: state, Nonce: l.Nonce, Verifier: l.Verifier})
	if err != nil {
		s.log.Warn("code exchange", zap.Error(err))
		fail(c, http.StatusUnauthorized, "login_failed", "sign-in was not completed")
		return
	}
	sess := session.Session{
		AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, IDToken: t.IDToken, ExpiresAt: t.ExpiresAt,
	}
	if t.ID != nil {
		sess.Subject, sess.IDPSessionID = t.ID.Subject, t.ID.SessionID
	}
	if sess.Subject == "" {
		fail(c, http.StatusUnauthorized, "login_failed", "sign-in was not completed")
		return
	}
	id, err := s.sessions.Create(ctx, sess)
	if err != nil {
		s.log.Error("create session", zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "unavailable", "sign-in is unavailable")
		return
	}
	s.clearCookie(c, retryCookie)
	// a new id at every login: no session fixation
	s.setCookie(c, sessionCookie, id, 0)
	c.Redirect(http.StatusFound, l.ReturnTo)
}

// ---- session access ----

// authenticate returns the session id, the session (tokens fresh) and the principal, or writes 401.
func (s *Server) authenticate(c *gin.Context) (string, *session.Session, *authn.Principal, bool) {
	if isBearer(c) {
		return s.authenticateBearer(c)
	}
	ctx := c.Request.Context()
	id := s.cookie(c, sessionCookie)
	if id == "" {
		fail(c, http.StatusUnauthorized, "unauthenticated", "sign in first")
		return "", nil, nil, false
	}
	sess, err := s.sessions.Get(ctx, id)
	if errors.Is(err, session.ErrNotFound) {
		s.clearCookie(c, sessionCookie)
		fail(c, http.StatusUnauthorized, "unauthenticated", "sign in first")
		return "", nil, nil, false
	}
	if err != nil {
		s.log.Error("load session", zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "unavailable", "try again")
		return "", nil, nil, false
	}
	if s.now().Add(30 * time.Second).After(sess.ExpiresAt) {
		if sess, err = s.refresh(ctx, id, sess); err != nil {
			if errors.Is(err, session.ErrNotFound) {
				s.clearCookie(c, sessionCookie)
				fail(c, http.StatusUnauthorized, "unauthenticated", "sign in again")
			} else {
				s.log.Error("refresh session", zap.Error(err))
				fail(c, http.StatusServiceUnavailable, "unavailable", "try again")
			}
			return "", nil, nil, false
		}
	}
	p, err := authn.Verify(ctx, s.verifier, sess.AccessToken)
	if err != nil {
		// a token that no longer verifies (key rotated away, revoked user): the session is over
		if apperror.From(err).HTTPStatus() == http.StatusUnauthorized {
			_ = s.sessions.Delete(ctx, id)
			s.clearCookie(c, sessionCookie)
			fail(c, http.StatusUnauthorized, "unauthenticated", "sign in again")
		} else {
			fail(c, http.StatusServiceUnavailable, "unavailable", "try again")
		}
		return "", nil, nil, false
	}
	httpx.SetPrincipal(c, p)
	return id, sess, p, true
}

// authenticateBearer verifies the access token of a mobile app or a service locally (signature,
// issuer, audience, expiry). There is no session: the client refreshes its own tokens with
// identity, and nothing is stored here. A revoked token stays valid until it expires, so keep
// the access token lifetime short. The returned session only carries the token, which is the
// subject token of the exchange for the upstream.
func (s *Server) authenticateBearer(c *gin.Context) (string, *session.Session, *authn.Principal, bool) {
	tok := bearerToken(c)
	if tok == "" {
		c.Header("WWW-Authenticate", "Bearer")
		fail(c, http.StatusUnauthorized, "unauthenticated", "send the access token as Authorization: Bearer")
		return "", nil, nil, false
	}
	p, err := authn.Verify(c.Request.Context(), s.verifier, tok)
	if err != nil {
		if apperror.From(err).HTTPStatus() == http.StatusUnauthorized {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			fail(c, http.StatusUnauthorized, "unauthenticated", "the access token is not valid")
		} else {
			fail(c, http.StatusServiceUnavailable, "unavailable", "try again")
		}
		return "", nil, nil, false
	}
	httpx.SetPrincipal(c, p)
	return "", &session.Session{AccessToken: tok, Subject: p.Subject}, p, true
}

// refresh renews the tokens; one replica does it, the others wait for its result.
func (s *Server) refresh(ctx context.Context, id string, sess *session.Session) (*session.Session, error) {
	if sess.RefreshToken == "" {
		_ = s.sessions.Delete(ctx, id)
		return nil, session.ErrNotFound
	}
	got, err := s.sessions.Lock(ctx, id, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if !got {
		deadline := s.now().Add(3 * time.Second)
		for s.now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			cur, err := s.sessions.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			if s.now().Add(30 * time.Second).Before(cur.ExpiresAt) {
				return cur, nil
			}
		}
		return nil, errors.New("refresh in progress elsewhere")
	}
	defer s.sessions.Unlock(ctx, id)
	// another replica may have refreshed between our read and the lock
	if cur, err := s.sessions.Get(ctx, id); err == nil && s.now().Add(30*time.Second).Before(cur.ExpiresAt) {
		return cur, nil
	}
	t, err := s.oidc.Refresh(ctx, sess.RefreshToken)
	if errors.Is(err, oidcclient.ErrInvalidGrant) {
		_ = s.sessions.Delete(ctx, id) // revoked, expired or reused refresh token
		return nil, session.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	next := *sess
	next.AccessToken, next.ExpiresAt = t.AccessToken, t.ExpiresAt
	if t.RefreshToken != "" {
		next.RefreshToken = t.RefreshToken
	}
	if t.IDToken != "" {
		next.IDToken = t.IDToken
	}
	if err := s.sessions.Update(ctx, id, next); err != nil {
		return nil, err
	}
	return &next, nil
}

// checkOrigin guards state changing requests: the Origin must be one of ours and the CSRF
// token of the session must be echoed in the Csrf-Token header.
func (s *Server) checkWrite(c *gin.Context, sess *session.Session) bool {
	origin := c.GetHeader("Origin")
	if origin == "" || !slices.Contains(s.cfg.Origins, origin) {
		fail(c, http.StatusForbidden, "bad_origin", "request origin is not allowed")
		return false
	}
	if !session.CSRFEqual(sess, c.GetHeader(csrfHeader)) {
		fail(c, http.StatusForbidden, "bad_csrf", "missing or invalid "+csrfHeader+" header")
		return false
	}
	return true
}

func (s *Server) me(c *gin.Context) {
	_, sess, p, ok := s.authenticate(c)
	if !ok {
		return
	}
	out := gin.H{
		"sub": p.Subject, "roles": p.Roles, "scopes": p.Scopes, "perms": p.Perms,
		"amr": p.AMR, "csrf_token": sess.CSRF, "expires_at": sess.ExpiresAt.UTC(),
	}
	// who to show in the UI: the profile claims of the ID token that identity issued at sign in
	name, email := profileClaims(sess.IDToken)
	if name != "" {
		out["name"] = name
	}
	if email != "" {
		out["email"] = email
	}
	c.JSON(http.StatusOK, out)
}

// profileClaims reads name and email from an ID token. The token comes from the sealed server side
// session (identity's answer to the code exchange, which the OIDC client verified), and the result is
// only displayed, so the signature is not checked again here.
func profileClaims(idToken string) (name, email string) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return "", ""
	}
	return c.Name, c.Email
}

func (s *Server) logout(c *gin.Context) {
	ctx := c.Request.Context()
	id := s.cookie(c, sessionCookie)
	// where identity sends the browser afterwards: the web app that asked (return_to=https://dict.example.com/),
	// which must be a UI origin and registered as a post logout URI of the client
	back := safeReturn(c.Query("return_to"), "", s.cfg.Origins)
	if back == "" || back[0] == '/' {
		back = s.cfg.PublicURL + "/"
	}
	sess, err := s.sessions.Get(ctx, id)
	if err != nil {
		s.clearCookie(c, sessionCookie)
		c.JSON(http.StatusOK, gin.H{"logout_url": back})
		return
	}
	if !s.checkWrite(c, sess) {
		return
	}
	_ = s.sessions.Delete(ctx, id)
	s.clearCookie(c, sessionCookie)
	if sess.RefreshToken != "" {
		if err := s.oidc.Revoke(ctx, sess.RefreshToken, "refresh_token"); err != nil {
			s.log.Warn("revoke refresh token", zap.Error(err))
		}
	}
	out := back
	if u, err := s.oidc.EndSessionURL(sess.IDToken, back, ""); err == nil {
		out = u
	}
	c.JSON(http.StatusOK, gin.H{"logout_url": out})
}

func (s *Server) backchannelLogout(c *gin.Context) {
	ctx := c.Request.Context()
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	claims, err := s.oidc.VerifyLogoutToken(ctx, c.PostForm("logout_token"))
	if err != nil {
		fail(c, http.StatusBadRequest, "invalid_request", "invalid logout token")
		return
	}
	var n int
	if claims.SessionID != "" {
		n, err = s.sessions.DeleteByIDPSession(ctx, claims.SessionID)
	} else {
		n, err = s.sessions.DeleteBySubject(ctx, claims.Subject)
	}
	if err != nil {
		s.log.Error("back-channel logout", zap.Error(err))
		fail(c, http.StatusServiceUnavailable, "unavailable", "try again")
		return
	}
	s.log.Info("back-channel logout", zap.String("sub", claims.Subject), zap.Int("sessions", n))
	c.Status(http.StatusOK)
}

// ---- system status ----

// systemStatus answers the applications of ArgoCD for users who hold system:status:read (deny by default,
// like a route without `public`). Not a gRPC route, so it is not in routes.yaml.
func (s *Server) systemStatus(c *gin.Context) {
	_, _, p, ok := s.authenticate(c)
	if !ok {
		return
	}
	if !p.Can(StatusPermission) {
		fail(c, http.StatusForbidden, "forbidden", "you are not allowed to do this")
		return
	}
	if s.status == nil {
		fail(c, http.StatusNotFound, "not_configured", "the system status is not configured")
		return
	}
	apps, err := s.status.Apps(c.Request.Context())
	if err != nil {
		s.log.Warn("system status", zap.Error(err))
		fail(c, http.StatusBadGateway, "unavailable", "the system status could not be read")
		return
	}
	c.JSON(http.StatusOK, gin.H{"apps": apps, "checkedAt": s.now().UTC()})
}

// ---- routes ----

func (s *Server) route(rt routes.Route) gin.HandlerFunc {
	if rt.Anonymous {
		return s.anonymousDownload(rt)
	}
	return func(c *gin.Context) {
		_, sess, p, ok := s.authenticate(c)
		if !ok {
			return
		}
		// the Origin and CSRF checks protect cookies the browser sends by itself; a Bearer token is not
		if rt.Method != http.MethodGet && !isBearer(c) && !s.checkWrite(c, sess) {
			return
		}
		if !rt.Rule.Allows(p.Perms) {
			fail(c, http.StatusForbidden, "forbidden", "you are not allowed to do this")
			return
		}
		body, err := s.requestJSON(c, rt)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		tok, err := s.exch.ExchangeToken(c.Request.Context(), sess.AccessToken, rt.Audience)
		if err != nil {
			if errors.Is(err, tokenexchange.ErrDenied) {
				fail(c, http.StatusForbidden, "forbidden", "you are not allowed to do this")
			} else {
				s.log.Error("token exchange", zap.Error(err), zap.String("audience", rt.Audience))
				fail(c, http.StatusBadGateway, "unavailable", "upstream authorization is unavailable")
			}
			return
		}
		if rt.Stream {
			s.streamFile(c, rt, body, tok)
			return
		}
		out, err := s.caller.Call(c.Request.Context(), rt, body, tok)
		if err != nil {
			s.writeError(c, rt, err)
			return
		}
		if rt.Download {
			s.writeFile(c, rt, out)
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", out)
	}
}

// anonymousDownload serves a route without a session: the secret in the path is the authorization and
// the upstream is called with the service token of gatekeeper. It is meant for an app (an Anki app)
// that fetches a link without cookies.
func (s *Server) anonymousDownload(rt routes.Route) gin.HandlerFunc {
	return func(c *gin.Context) {
		// the last parameter may carry a file extension (.apkg) that only makes the link look like a file
		if n := len(c.Params); n > 0 {
			c.Params[n-1].Value = strings.TrimSuffix(c.Params[n-1].Value, path.Ext(c.Params[n-1].Value))
		}
		body, err := s.requestJSON(c, rt)
		if err != nil {
			fail(c, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		tok, err := s.exch.ServiceToken(c.Request.Context(), rt.Audience)
		if err != nil {
			s.log.Error("service token", zap.Error(err), zap.String("audience", rt.Audience))
			fail(c, http.StatusBadGateway, "unavailable", "upstream authorization is unavailable")
			return
		}
		if rt.Stream {
			s.streamFile(c, rt, body, tok)
			return
		}
		out, err := s.caller.Call(c.Request.Context(), rt, body, tok)
		if err != nil {
			s.writeError(c, rt, err)
			return
		}
		s.writeFile(c, rt, out)
	}
}

// streamWriteWindow is how long one chunk of a streamed download may take to reach the client. The server's
// WriteTimeout would cut a large download at once; the deadline moves on after every chunk, so only a client that
// stalls is cut.
const streamWriteWindow = 30 * time.Second

// streamFile answers a download route with stream: true. The first chunk gives the headers (the file name and the
// size, so the browser shows the progress), every chunk is written and flushed as it arrives: the file is never
// held whole. An error before the first byte is an ordinary error answer; after it the connection is aborted, so
// the client sees a failed download and not a short file.
func (s *Server) streamFile(c *gin.Context, rt routes.Route, body []byte, tok string) {
	rc := http.NewResponseController(c.Writer)
	var (
		started bool
		want    int64
		wrote   int64
	)
	err := s.caller.CallStream(c.Request.Context(), rt, body, tok, func(m *dynamicpb.Message) error {
		d := m.Descriptor().Fields()
		if !started {
			started = true
			name := m.Get(d.ByName("filename")).String()
			if name == "" {
				name = "download"
			}
			want = m.Get(d.ByName("size")).Int()
			c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
			c.Header("Content-Type", "application/octet-stream")
			c.Header("Content-Length", strconv.FormatInt(want, 10))
			c.Status(http.StatusOK)
		}
		data := m.Get(d.ByName("data")).Bytes()
		_ = rc.SetWriteDeadline(s.now().Add(streamWriteWindow))
		n, err := c.Writer.Write(data)
		wrote += int64(n)
		if err != nil {
			return err
		}
		c.Writer.Flush()
		return nil
	})
	if err == nil && started && wrote == want {
		return
	}
	if err == nil {
		if !started {
			err = errors.New("the stream carried no message")
		} else {
			err = errors.New("the stream ended before the whole file")
		}
	}
	if !started {
		s.writeError(c, rt, err)
		return
	}
	if c.Request.Context().Err() == nil {
		s.log.Error("download stream broke", zap.Error(err), zap.String("grpc", rt.GRPC), zap.Int64("wrote", wrote), zap.Int64("size", want))
	}
	panic(http.ErrAbortHandler)
}

// writeFile answers a download route: the reply has `filename` and `data` (base64 in the JSON).
func (s *Server) writeFile(c *gin.Context, rt routes.Route, reply []byte) {
	var r struct {
		Filename string `json:"filename"`
		Data     string `json:"data"`
	}
	var data []byte
	err := json.Unmarshal(reply, &r)
	if err == nil {
		data, err = base64.StdEncoding.DecodeString(r.Data)
	}
	if err != nil {
		s.log.Error("download reply", zap.Error(err), zap.String("grpc", rt.GRPC))
		fail(c, http.StatusBadGateway, "unavailable", "the service returned an unreadable file")
		return
	}
	name := r.Filename
	if name == "" {
		name = "download"
	}
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	c.Data(http.StatusOK, "application/octet-stream", data)
}

// requestJSON builds the gRPC request: the JSON body (an object) plus the path parameters and
// the query string, which fill top level fields (path parameters win).
func (s *Server) requestJSON(c *gin.Context, rt routes.Route) ([]byte, error) {
	obj := map[string]any{}
	if c.Request.Body != nil && c.Request.ContentLength != 0 && rt.Method != http.MethodGet {
		if ct := c.GetHeader("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "application/json") {
			return nil, errors.New("Content-Type must be application/json")
		}
		raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxBody))
		if err != nil {
			return nil, errors.New("request body is too large or unreadable")
		}
		if len(strings.TrimSpace(string(raw))) > 0 {
			if err := json.Unmarshal(raw, &obj); err != nil {
				return nil, errors.New("request body must be a JSON object")
			}
		}
	}
	for k, vs := range c.Request.URL.Query() {
		if len(vs) == 1 {
			obj[k] = vs[0]
		} else {
			obj[k] = vs
		}
	}
	for _, prm := range c.Params {
		obj[prm.Key] = prm.Value
	}
	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj)
}

func (s *Server) writeError(c *gin.Context, rt routes.Route, err error) {
	var pe *proxy.Error
	if errors.As(err, &pe) {
		if pe.Kind == proxy.KindBadRequest {
			fail(c, http.StatusBadRequest, "invalid_request", pe.Error())
			return
		}
		s.log.Error("upstream unavailable", zap.Error(err), zap.String("upstream", rt.Upstream))
		fail(c, http.StatusBadGateway, "unavailable", "the service is unavailable")
		return
	}
	st, _ := status.FromError(err)
	httpCode, code := mapCode(st.Code())
	msg := st.Message()
	if httpCode >= 500 {
		s.log.Error("upstream error", zap.Error(err), zap.String("upstream", rt.Upstream), zap.String("grpc", rt.GRPC))
		fail(c, httpCode, code, "the service failed to process the request") // no internal reason leaves the gateway
		return
	}
	reason, params := apperror.ReasonOf(st)
	fail(c, httpCode, code, msg, failure{reason: reason, params: params})
}

func mapCode(c codes.Code) (int, string) {
	switch c {
	case codes.InvalidArgument, codes.OutOfRange:
		return http.StatusBadRequest, "invalid_argument"
	case codes.NotFound:
		return http.StatusNotFound, "not_found"
	case codes.AlreadyExists, codes.Aborted:
		return http.StatusConflict, "conflict"
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed, "failed_precondition"
	case codes.PermissionDenied:
		return http.StatusForbidden, "forbidden"
	case codes.Unauthenticated:
		return http.StatusBadGateway, "upstream_auth" // gatekeeper's own token was refused: not the user's fault
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests, "rate_limited"
	case codes.Unavailable:
		return http.StatusServiceUnavailable, "unavailable"
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout, "timeout"
	case codes.Unimplemented:
		return http.StatusNotImplemented, "unimplemented"
	default:
		return http.StatusInternalServerError, "internal"
	}
}
