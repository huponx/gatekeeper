package routes

import (
	"os"
	"strings"
	"testing"

	"github.com/huponx/gocommon/grpcserver"
)

const head = "upstreams:\n  courier: {target: courier:9090}\nroutes:\n"

var rules = RuleMap{
	"courier.v1.CourierService/SendNotification": {Any: []string{"courier:notification:send"}},
	"courier.v1.CourierService/Get":              grpcserver.PublicRule,
	"p.S/M":                                      grpcserver.PublicRule,
	"p.S/N":                                      grpcserver.PublicRule,
}

func TestParse(t *testing.T) {
	tbl, err := Parse([]byte(head+`  - http: POST /api/notifications
    grpc: courier.v1.CourierService/SendNotification
    upstream: courier
  - http: GET /api/users/{id}
    grpc: courier.v1.CourierService/Get
    upstream: courier
    audience: other
`), rules)
	if err != nil {
		t.Fatal(err)
	}
	r := tbl.Routes[0]
	if r.Method != "POST" || r.Path != "/api/notifications" || r.Service != "courier.v1.CourierService" || r.RPC != "SendNotification" || r.Audience != "courier" {
		t.Fatalf("route: %+v", r)
	}
	if len(r.Rule.Any) != 1 || r.Rule.Any[0] != "courier:notification:send" {
		t.Fatalf("the rule comes from the proto: %+v", r.Rule)
	}
	if tbl.Routes[1].Audience != "other" || !tbl.Routes[1].Rule.Public {
		t.Fatalf("route: %+v", tbl.Routes[1])
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"rpc without a rule": "  - {http: GET /a, grpc: p.S/Unruled, upstream: courier}\n",
		"permission in yaml": "  - {http: GET /a, grpc: p.S/M, upstream: courier, permission: a:b}\n",
		"public in yaml":     "  - {http: GET /a, grpc: p.S/M, upstream: courier, public: true}\n",
		"bad method":         "  - {http: TRACE /a, grpc: p.S/M, upstream: courier}\n",
		"no slash":           "  - {http: GET a, grpc: p.S/M, upstream: courier}\n",
		"reserved":           "  - {http: GET /auth/me, grpc: p.S/M, upstream: courier}\n",
		"unknown upstream":   "  - {http: GET /a, grpc: p.S/M, upstream: nope}\n",
		"bad grpc":           "  - {http: GET /a, grpc: p.S, upstream: courier}\n",
		"duplicate":          "  - {http: GET /a, grpc: p.S/M, upstream: courier}\n  - {http: GET /a, grpc: p.S/N, upstream: courier}\n",
		"anonymous post":     "  - {http: POST /a, grpc: p.S/M, upstream: courier, anonymous: true, download: true}\n",
		"anonymous json":     "  - {http: GET /a, grpc: p.S/M, upstream: courier, anonymous: true}\n",
		"download post":      "  - {http: POST /a, grpc: p.S/M, upstream: courier, download: true}\n",
		"stream no download": "  - {http: GET /a, grpc: p.S/M, upstream: courier, stream: true}\n",
		"unknown field":      "  - {http: GET /a, grpc: p.S/M, upstream: courier, perm: x}\n",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(head+body), rules); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("upstreams:\n  a: {}\n"), rules); err == nil || !strings.Contains(err.Error(), "target") {
		t.Errorf("upstream without target: %v", err)
	}
	if _, err := Parse([]byte(head+"  - {http: GET /a, grpc: p.S/M, upstream: courier}\n"), nil); err == nil {
		t.Error("without descriptors the rule cannot be read: the route must be refused")
	}
	// an anonymous route needs no rule: the secret in the path is the authorization
	if _, err := Parse([]byte(head+"  - {http: \"GET /a/{t}\", grpc: p.S/Unruled, upstream: courier, anonymous: true, download: true}\n"), rules); err != nil {
		t.Errorf("anonymous: %v", err)
	}
}

// TestChartRoutes loads the routes the chart ships (the only copy) with the descriptor set it ships: every route
// must find the authz rule of its RPC there, and every permission a rule names must be declared in a permissions.proto.
func TestChartRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../routes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	files, err := LoadDescriptors("../../descriptors.binpb")
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Parse([]byte("upstreams:\n  identity: {target: \"identity:9090\"}\n  dictionary: {target: \"dictionary:9090\"}\n"+string(raw)), DescriptorRules(files))
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Routes) == 0 {
		t.Fatal("no routes")
	}
	declared := map[string]bool{}
	for _, path := range []string{"identity/v1/permissions.proto", "dictionary/v1/permissions.proto"} {
		fd, err := files.FindFileByPath(path)
		if err != nil {
			t.Fatalf("%s is not in descriptors.binpb (make descriptors): %v", path, err)
		}
		for _, d := range grpcserver.DeclaredPermissions(fd) {
			declared[d.Name] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("no declared permissions in the descriptor set")
	}
	for _, r := range tbl.Routes {
		if r.Anonymous { // no session: only the download of a deck, the token in the path is the authorization
			if r.Method != "GET" || !r.Download ||
				(!strings.HasPrefix(r.Path, "/api/dictionary/downloads/") && !strings.HasPrefix(r.Path, "/api/dictionary/export-downloads/")) {
				t.Errorf("%s %s: anonymous routes are only for the deck downloads", r.Method, r.Path)
			}
			if r.Stream != strings.HasPrefix(r.Path, "/api/dictionary/export-downloads/") {
				t.Errorf("%s %s: only the download of an export part streams", r.Method, r.Path)
			}
			continue
		}
		for _, name := range append(append([]string(nil), r.Rule.Any...), r.Rule.All...) {
			if !declared[name] {
				t.Errorf("%s %s: %s is not a declared permission", r.Method, r.Path, name)
			}
		}
	}
}

// A route for an RPC that has no rule does not load: the descriptor set of a proto with the option removed.
func TestRouteWithoutARuleDoesNotLoad(t *testing.T) {
	files, err := LoadDescriptors("../../descriptors.binpb")
	if err != nil {
		t.Fatal(err)
	}
	// the health service of grpc is in no descriptor set of ours, and a made-up method of identity has no option
	for _, grpc := range []string{"identity.v1.IdentityService/NoSuchMethod", "grpc.health.v1.Health/Check"} {
		_, err = Parse([]byte("upstreams:\n  identity: {target: x}\nroutes:\n  - {http: GET /a, grpc: "+grpc+", upstream: identity}\n"), DescriptorRules(files))
		if err == nil || !strings.Contains(err.Error(), "authz.v1.rule") {
			t.Errorf("%s: %v", grpc, err)
		}
	}
}

func TestRulesFromTheDescriptors(t *testing.T) {
	files, err := LoadDescriptors("../../descriptors.binpb")
	if err != nil {
		t.Fatal(err)
	}
	rules := DescriptorRules(files)
	if r, ok := rules.Rule("identity.v1.IdentityService", "ListUsers"); !ok || len(r.Any) != 2 || !r.Allows([]string{"identity:user:approve"}) || r.Allows([]string{"identity:user:write"}) {
		t.Errorf("ListUsers: %+v %v", r, ok)
	}
	if r, ok := rules.Rule("identity.v1.IdentityService", "GetMe"); !ok || !r.Public {
		t.Errorf("GetMe: %+v %v", r, ok)
	}
}
