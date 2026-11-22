package routes

import (
	"os"
	"strings"
	"testing"
)

const head = "upstreams:\n  courier: {target: courier:9090}\nroutes:\n"

func TestParse(t *testing.T) {
	tbl, err := Parse([]byte(head + `  - http: POST /api/notifications
    grpc: courier.v1.CourierService/SendNotification
    upstream: courier
    permission: courier:notification:send
  - http: GET /api/users/{id}
    grpc: courier.v1.CourierService/Get
    upstream: courier
    audience: other
    public: true
`))
	if err != nil {
		t.Fatal(err)
	}
	r := tbl.Routes[0]
	if r.Method != "POST" || r.Path != "/api/notifications" || r.Service != "courier.v1.CourierService" || r.RPC != "SendNotification" || r.Audience != "courier" {
		t.Fatalf("route: %+v", r)
	}
	if tbl.Routes[1].Audience != "other" || !tbl.Routes[1].Public {
		t.Fatalf("route: %+v", tbl.Routes[1])
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no permission":    "  - {http: GET /a, grpc: p.S/M, upstream: courier}\n",
		"both":             "  - {http: GET /a, grpc: p.S/M, upstream: courier, permission: a:b, public: true}\n",
		"bad method":       "  - {http: TRACE /a, grpc: p.S/M, upstream: courier, public: true}\n",
		"no slash":         "  - {http: GET a, grpc: p.S/M, upstream: courier, public: true}\n",
		"reserved":         "  - {http: GET /auth/me, grpc: p.S/M, upstream: courier, public: true}\n",
		"unknown upstream": "  - {http: GET /a, grpc: p.S/M, upstream: nope, public: true}\n",
		"bad grpc":         "  - {http: GET /a, grpc: p.S, upstream: courier, public: true}\n",
		"duplicate":        "  - {http: GET /a, grpc: p.S/M, upstream: courier, public: true}\n  - {http: GET /a, grpc: p.S/N, upstream: courier, public: true}\n",
		"unknown field":    "  - {http: GET /a, grpc: p.S/M, upstream: courier, public: true, perm: x}\n",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(head + body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("upstreams:\n  a: {}\n")); err == nil || !strings.Contains(err.Error(), "target") {
		t.Errorf("upstream without target: %v", err)
	}
}

// TestChartRoutes checks the routes the chart ships (the only copy), with the upstream of the chart values.
func TestChartRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../routes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Parse([]byte("upstreams:\n  identity: {target: \"identity:9090\"}\n" + string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl.Routes) == 0 {
		t.Fatal("no routes")
	}
	for _, r := range tbl.Routes {
		if !strings.HasPrefix(r.Permission, "identity:") {
			t.Errorf("%s %s: permission %q", r.Method, r.Path, r.Permission)
		}
	}
}
