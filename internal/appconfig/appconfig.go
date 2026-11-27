package appconfig

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/huponx/gocommon/config"
)

type Gatekeeper struct {
	config.Log
	config.Redis

	Host            string        `env:"HOST" envDefault:"0.0.0.0"`
	Port            int           `env:"PORT" envDefault:"8080"`
	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`

	// PublicURL is the address of this gateway (https://api.example.com). The OIDC redirect URI is
	// PublicURL + /auth/callback and must be registered on the identity client.
	PublicURL string `env:"GATEKEEPER_PUBLIC_URL,required"`
	// UIOrigins are the web apps allowed to call the gateway from a browser, for example
	// "https://dict.example.com,https://bill.example.com" (separated by commas, spaces or new lines).
	// They get CORS, may be the target of
	// return_to / post logout redirects, and are the Origin values accepted on state changing
	// requests. Empty means only PublicURL itself (same origin use).
	UIOrigins []string `env:"GATEKEEPER_UI_ORIGINS" envSeparator:","`
	// AllowedOrigins is the former name of UIOrigins and is kept as an alias.
	AllowedOrigins []string `env:"GATEKEEPER_ALLOWED_ORIGINS" envSeparator:","`
	// RoutesFile is the routes YAML (see README).
	RoutesFile string `env:"GATEKEEPER_ROUTES_FILE" envDefault:"/etc/gatekeeper/routes.yaml"`

	// IdentityIssuer is the issuer URL of identity. IdentityURL is how this process reaches it
	// when that differs from the issuer (cluster internal address); empty means the issuer.
	IdentityIssuer string `env:"GATEKEEPER_IDENTITY_ISSUER,required"`
	ClientID       string `env:"GATEKEEPER_CLIENT_ID,required"`
	ClientSecret   string `env:"GATEKEEPER_CLIENT_SECRET,required"`
	// Audience is the resource of the client: the aud of the user tokens the BFF holds.
	Audience string `env:"GATEKEEPER_AUDIENCE,required"`

	// SessionKeys seal the tokens stored in Redis: "id:base64key" (32 bytes), comma separated, the
	// first seals, the others only open (rotation).
	SessionKeys        []string      `env:"GATEKEEPER_SESSION_KEY,required" envSeparator:","`
	SessionIdleTTL     time.Duration `env:"GATEKEEPER_SESSION_IDLE_TTL" envDefault:"8h"`
	SessionAbsoluteTTL time.Duration `env:"GATEKEEPER_SESSION_ABSOLUTE_TTL" envDefault:"168h"`

	// PostLoginURL is where the browser lands when login started without a return address.
	PostLoginURL string `env:"GATEKEEPER_POST_LOGIN_URL" envDefault:"/"`
	// PortalURL is the portal: GET / redirects there, and it is where login lands unless GATEKEEPER_POST_LOGIN_URL
	// says otherwise. Optional; without it GET / answers 404.
	PortalURL string `env:"GATEKEEPER_PORTAL_URL"`
	// DefaultACR, when set (for example "mfa"), is requested on every login.
	DefaultACR string `env:"GATEKEEPER_ACR_VALUES"`

	// ArgoCDURL turns on GET /api/system/status (the status of the applications for the admin app):
	// the address of argocd-server, for example http://argocd-server.argocd.svc. ArgoCDToken is the API
	// token of a read-only account, ArgoCDProject limits the list to one ArgoCD project.
	ArgoCDURL     string `env:"GATEKEEPER_ARGOCD_URL"`
	ArgoCDToken   string `env:"GATEKEEPER_ARGOCD_TOKEN"`
	ArgoCDProject string `env:"GATEKEEPER_ARGOCD_PROJECT"`

	// UpstreamInsecure dials the upstreams without TLS (in-cluster traffic). Per upstream
	// overrides live in the routes file.
	UpstreamInsecure bool `env:"GATEKEEPER_UPSTREAM_INSECURE" envDefault:"true"`
	// UpstreamMaxRecvBytes is the largest message gatekeeper accepts from an upstream. A synchronous export
	// (dictionary: DICTIONARY_EXPORT_MAX_BYTES_CEILING, 10 MiB by default) travels in one message, so keep it
	// above that ceiling plus a margin; the parts of an export job are streamed in small chunks.
	UpstreamMaxRecvBytes int `env:"GATEKEEPER_UPSTREAM_MAX_RECV_BYTES" envDefault:"16777216"`
}

func (c Gatekeeper) Addr() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

// Origins returns the accepted browser origins: the UI origins (or the former
// GATEKEEPER_ALLOWED_ORIGINS), or the gateway's own origin when none is configured.
func (c Gatekeeper) Origins() []string {
	var out []string
	// config.Fields: comma, space or new line separated (a YAML block scalar in the deployment values)
	for _, o := range config.Fields(append(append([]string{}, c.UIOrigins...), c.AllowedOrigins...)) {
		if o = strings.TrimRight(o, "/"); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	if len(out) > 0 {
		return out
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return nil
	}
	return []string{u.Scheme + "://" + u.Host}
}

func (c Gatekeeper) IsLocal() bool { return strings.EqualFold(c.Env, "local") }

// Validate rejects settings that would start the service unsafely.
func (c Gatekeeper) Validate() error {
	if err := config.ValidatePort(c.Port); err != nil {
		return err
	}
	if !c.IsLocal() && !strings.HasPrefix(c.PublicURL, "https://") {
		return fmt.Errorf("GATEKEEPER_PUBLIC_URL must be https outside ENV=local (the session cookie is Secure)")
	}
	if _, err := url.Parse(c.PublicURL); err != nil {
		return fmt.Errorf("GATEKEEPER_PUBLIC_URL: %w", err)
	}
	if c.PortalURL != "" {
		u, err := url.Parse(c.PortalURL)
		if err != nil || u.Host == "" || !(u.Scheme == "https" || (c.IsLocal() && u.Scheme == "http")) {
			return fmt.Errorf("GATEKEEPER_PORTAL_URL must be an https URL (http only with ENV=local), got %q", c.PortalURL)
		}
	}
	for _, o := range c.Origins() {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("GATEKEEPER_UI_ORIGINS: %q is not an origin (scheme://host[:port])", o)
		}
		if !c.IsLocal() && u.Scheme != "https" {
			return fmt.Errorf("GATEKEEPER_UI_ORIGINS: %q must be https outside ENV=local", o)
		}
	}
	if (c.ArgoCDURL == "") != (c.ArgoCDToken == "") {
		return fmt.Errorf("GATEKEEPER_ARGOCD_URL and GATEKEEPER_ARGOCD_TOKEN go together (both or neither)")
	}
	if c.UpstreamMaxRecvBytes != 0 && c.UpstreamMaxRecvBytes < 1<<20 {
		return fmt.Errorf("GATEKEEPER_UPSTREAM_MAX_RECV_BYTES must be at least 1048576")
	}
	if c.SessionAbsoluteTTL < c.SessionIdleTTL {
		return fmt.Errorf("GATEKEEPER_SESSION_ABSOLUTE_TTL must not be shorter than GATEKEEPER_SESSION_IDLE_TTL")
	}
	return nil
}
