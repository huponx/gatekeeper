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
// means any signed-in user: deny by default.
package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"

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
		if r.Permission == "" && !r.Public {
			return nil, fmt.Errorf("routes[%d] %s: set permission, or public: true for any signed-in user", i, key)
		}
		if r.Permission != "" && r.Public {
			return nil, fmt.Errorf("routes[%d] %s: permission and public are exclusive", i, key)
		}
	}
	return &t, nil
}
