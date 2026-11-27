package proxy

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gocommon/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// authCheck records the authorization metadata the upstream received.
type authCheck struct{ got string }

func (a *authCheck) unary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("authorization"); len(v) > 0 {
			a.got = v[0]
		}
	}
	return h(ctx, req)
}

func upstream(t *testing.T) (Dialer, *authCheck) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	ac := &authCheck{}
	srv := grpc.NewServer(grpc.UnaryInterceptor(ac.unary))
	hs := health.NewServer()
	hs.SetServingStatus("up", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)
	reflection.Register(srv)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return func(ctx context.Context, name string, u routes.Upstream) (grpc.ClientConnInterface, error) {
		return grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}, ac
}

func table(t *testing.T) *routes.Table {
	t.Helper()
	tbl, err := routes.Parse([]byte(`upstreams:
  health: {target: x}
routes:
  - {http: GET /health, grpc: grpc.health.v1.Health/Check, upstream: health}
  - {http: GET /nope, grpc: grpc.health.v1.Health/Missing, upstream: health}
  - {http: GET /watch, grpc: grpc.health.v1.Health/Watch, upstream: health}
`), routes.RuleMap{
		"grpc.health.v1.Health/Check": grpcserver.PublicRule, "grpc.health.v1.Health/Missing": grpcserver.PublicRule, "grpc.health.v1.Health/Watch": grpcserver.PublicRule,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func TestCallThroughReflection(t *testing.T) {
	dial, ac := upstream(t)
	p, err := New(table(t), dial)
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Call(context.Background(), p.table.Routes[0], []byte(`{"service":"up"}`), "tok123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"SERVING"`) {
		t.Fatalf("reply: %s", out)
	}
	if ac.got != "Bearer tok123" {
		t.Fatalf("upstream authorization = %q", ac.got)
	}

	// the status of the upstream passes through
	_, err = p.Call(context.Background(), p.table.Routes[0], []byte(`{"service":"unknown"}`), "t")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}

	// malformed JSON and unknown fields are bad requests (gatekeeper's own error)
	for _, body := range []string{`{`, `{"nope":1}`} {
		_, err = p.Call(context.Background(), p.table.Routes[0], []byte(body), "t")
		if pe, ok := err.(*Error); !ok || pe.Kind != KindBadRequest {
			t.Fatalf("%s: want bad request, got %v", body, err)
		}
	}

	// unresolvable and streaming routes
	for _, i := range []int{1, 2} {
		_, err = p.Call(context.Background(), p.table.Routes[i], nil, "t")
		if pe, ok := err.(*Error); !ok || pe.Kind != KindUnavailable {
			t.Fatalf("route %d: want unavailable, got %v", i, err)
		}
	}
	if err := p.Check(context.Background()); err == nil {
		t.Fatal("Check must report the bad routes")
	}
}
