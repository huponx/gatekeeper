// Package routes loads the route table of gatekeeper: which HTTP request becomes which gRPC
// call, on which upstream, and what the caller must be allowed to do.
//
//	descriptors: /etc/gatekeeper/descriptors.binpb   # optional, else gRPC reflection
//	upstreams:
//	  courier: {target: courier.application.svc:9090}
//	routes:
//	  - http: POST /api/notifications
//	    grpc: courier.v1.CourierService/SendNotification
//	    upstream: courier
//	    audience: courier                  # aud of the exchanged token, default: the upstream name
//	    permission: courier:notification:send
//
// A route without "permission" is refused at load time unless it says `public: true`, which
// means any signed-in user, or `anonymous: true` (a download link, see Route): deny by default.
package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Upstream struct {
	Target string `yaml:"target"`
	// Insecure overrides GATEKEEPER_UPSTREAM_INSECURE for this upstream.
	Insecure *bool `yaml:"insecure"`
}

type Route struct {
	HTTP       string `yaml:"http"`
	GRPC       string `yaml:"grpc"`
	Upstream   string `yaml:"upstream"`
	Audience   string `yaml:"audience"`
	Permission string `yaml:"permission"`
	// Public: any signed-in user may call (no permission needed). Never anonymous.
	Public bool `yaml:"public"`
	// Anonymous: no session at all, for a link that is itself the secret (the download of an Anki deck).
	// Gatekeeper calls the upstream with its own service token. Only for a GET with `download: true`.
	Anonymous bool `yaml:"anonymous"`
	// Timeout is the deadline of the call to the upstream; default is the one of the gRPC client (5s).
	// Set it for a method that does real work (building an Anki deck downloads audio files).
	Timeout time.Duration `yaml:"timeout"`
	// Download: the reply message has the fields `filename` (string) and `data` (bytes), and the HTTP
	// answer is that file (an attachment) instead of JSON. The last path segment may end in an extension
	// (/downloads/{token}.apkg): the extension is dropped from the parameter.
	Download bool `yaml:"download"`

	Method string `yaml:"-"`
	Path   string `yaml:"-"`
	// Service and RPC are the halves of GRPC ("courier.v1.CourierService", "SendNotification").
	Service string `yaml:"-"`
	RPC     string `yaml:"-"`
}

type Table struct {
	// Descriptors is a protobuf FileDescriptorSet (buf build -o descriptors.binpb) that describes
	// every routed service. Without it gatekeeper asks the upstreams through gRPC reflection,
	// which production services normally keep off.
	Descriptors string              `yaml:"descriptors"`
	Upstreams   map[string]Upstream `yaml:"upstreams"`
	Routes      []Route             `yaml:"routes"`
}

// Load reads and validates a routes file.
func Load(path string) (*Table, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse validates a routes document.
func Parse(b []byte) (*Table, error) {
	var t Table
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("routes: %w", err)
	}
	for name, u := range t.Upstreams {
		if u.Target == "" {
			return nil, fmt.Errorf("routes: upstream %q has no target", name)
		}
	}
	seen := map[string]bool{}
	for i := range t.Routes {
		r := &t.Routes[i]
		method, path, ok := strings.Cut(strings.TrimSpace(r.HTTP), " ")
		path = strings.TrimSpace(path)
		if !ok || !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("routes[%d]: http must be \"METHOD /path\", got %q", i, r.HTTP)
		}
		switch method {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return nil, fmt.Errorf("routes[%d]: method %q is not supported", i, method)
		}
		if strings.HasPrefix(path, "/auth/") || path == "/auth" || strings.HasPrefix(path, "/healthz") || strings.HasPrefix(path, "/readyz") {
			return nil, fmt.Errorf("routes[%d]: %s is reserved", i, path)
		}
		r.Method, r.Path = method, path
		key := method + " " + path
		if seen[key] {
			return nil, fmt.Errorf("routes[%d]: %s is declared twice", i, key)
		}
		seen[key] = true

		svc, rpc, ok := strings.Cut(r.GRPC, "/")
		if !ok || svc == "" || rpc == "" || strings.Contains(rpc, "/") {
			return nil, fmt.Errorf("routes[%d]: grpc must be \"package.Service/Method\", got %q", i, r.GRPC)
		}
		r.Service, r.RPC = svc, rpc
		if _, ok := t.Upstreams[r.Upstream]; !ok {
			return nil, fmt.Errorf("routes[%d]: unknown upstream %q", i, r.Upstream)
		}
		if r.Audience == "" {
			r.Audience = r.Upstream
		}
		if r.Download && method != http.MethodGet {
			return nil, fmt.Errorf("routes[%d] %s: download is only for GET", i, key)
		}
		if r.Anonymous && (method != http.MethodGet || !r.Download) {
			return nil, fmt.Errorf("routes[%d] %s: anonymous is only for a GET with download: true", i, key)
		}
		if r.Permission == "" && !r.Public && !r.Anonymous {
			return nil, fmt.Errorf("routes[%d] %s: set permission, or public: true for any signed-in user", i, key)
		}
		if n := b2i(r.Permission != "") + b2i(r.Public) + b2i(r.Anonymous); n > 1 {
			return nil, fmt.Errorf("routes[%d] %s: permission, public and anonymous are exclusive", i, key)
		}
	}
	return &t, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
