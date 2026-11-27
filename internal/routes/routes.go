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
//
// A route has no permission of its own: who may call it is the `authz.v1.rule` option of the RPC in its proto
// (any_of, all_of or public), read from the descriptor set, the same rule the service enforces. A route whose RPC has
// none is refused at load time (deny by default), unless it says `anonymous: true` (a download link, see Route).
package routes

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/huponx/gocommon/grpcserver"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"gopkg.in/yaml.v3"
)

// Rules finds the authorization rule of an RPC ("pkg.Service", "Method").
type Rules interface {
	Rule(service, rpc string) (grpcserver.Rule, bool)
}

// RuleMap is Rules over a map keyed "pkg.Service/Method" (tests).
type RuleMap map[string]grpcserver.Rule

func (m RuleMap) Rule(service, rpc string) (grpcserver.Rule, bool) {
	r, ok := m[service+"/"+rpc]
	return r, ok
}

type fileRules struct{ files *protoregistry.Files }

// DescriptorRules reads the `authz.v1.rule` option of the methods of a descriptor set. A method with no rule, or
// with more than one of any_of, all_of and public, is not found.
func DescriptorRules(files *protoregistry.Files) Rules { return fileRules{files} }

func (f fileRules) Rule(service, rpc string) (grpcserver.Rule, bool) {
	d, err := f.files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return grpcserver.Rule{}, false
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return grpcserver.Rule{}, false
	}
	md := sd.Methods().ByName(protoreflect.Name(rpc))
	if md == nil {
		return grpcserver.Rule{}, false
	}
	return grpcserver.RuleOf(md)
}

// LoadDescriptors reads a FileDescriptorSet (buf build -o descriptors.binpb).
func LoadDescriptors(path string) (*protoregistry.Files, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(b, &set); err != nil {
		return nil, fmt.Errorf("descriptors: %w", err)
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("descriptors: %w", err)
	}
	return files, nil
}

type Upstream struct {
	Target string `yaml:"target"`
	// Insecure overrides GATEKEEPER_UPSTREAM_INSECURE for this upstream.
	Insecure *bool `yaml:"insecure"`
}

type Route struct {
	HTTP     string `yaml:"http"`
	GRPC     string `yaml:"grpc"`
	Upstream string `yaml:"upstream"`
	Audience string `yaml:"audience"`
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
	// Stream: the method is server-streaming and the reply messages are chunks of the file: the first one has
	// `filename` (string) and `size` (int64), every one has `data` (bytes). The HTTP answer is that file, written
	// as the chunks arrive, so a file larger than a gRPC message never sits whole in memory. Only with `download: true`.
	Stream bool `yaml:"stream"`

	Method string `yaml:"-"`
	Path   string `yaml:"-"`
	// Rule is who may call it, from the proto of the RPC (empty for an anonymous route, which has no session).
	Rule grpcserver.Rule `yaml:"-"`
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

	// Files is the loaded descriptor set (set by Load).
	Files *protoregistry.Files `yaml:"-"`
}

// Load reads and validates a routes file; its `descriptors` file gives the rule of every route.
func Load(path string) (*Table, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var head struct {
		Descriptors string `yaml:"descriptors"`
	}
	if err := yaml.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("routes: %w", err)
	}
	if head.Descriptors == "" {
		return nil, fmt.Errorf("routes: descriptors is required: the permission of a route is the authz rule of its RPC")
	}
	files, err := LoadDescriptors(head.Descriptors)
	if err != nil {
		return nil, err
	}
	t, err := Parse(b, DescriptorRules(files))
	if err != nil {
		return nil, err
	}
	t.Files = files
	return t, nil
}

// Parse validates a routes document. rules gives the authorization rule of each RPC: a route whose RPC has none is
// refused, except an anonymous one.
func Parse(b []byte, rules Rules) (*Table, error) {
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
		if r.Stream && !r.Download {
			return nil, fmt.Errorf("routes[%d] %s: stream is only for a route with download: true", i, key)
		}
		if r.Anonymous && (method != http.MethodGet || !r.Download) {
			return nil, fmt.Errorf("routes[%d] %s: anonymous is only for a GET with download: true", i, key)
		}
		if !r.Anonymous {
			if rules == nil {
				return nil, fmt.Errorf("routes[%d] %s: no descriptors to read the rule of %s from", i, key, r.GRPC)
			}
			rule, ok := rules.Rule(svc, rpc)
			if !ok {
				return nil, fmt.Errorf("routes[%d] %s: %s has no authz.v1.rule (exactly one of any_of, all_of, public) in its proto", i, key, r.GRPC)
			}
			r.Rule = rule
		}
	}
	return &t, nil
}
