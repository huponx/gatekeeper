package proxy

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc"

	"github.com/huponx/gatekeeper/internal/routes"
)

// TestChartRoutesMatchDescriptors checks that the descriptor set the chart ships (descriptors.binpb,
// made by `make descriptors`) knows every method of the routes the chart ships. A failure means the
// file is stale: run `make descriptors` after a change in ../protos.
func TestChartRoutesMatchDescriptors(t *testing.T) {
	raw, err := os.ReadFile("../../routes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := routes.Parse([]byte("descriptors: ../../descriptors.binpb\nupstreams:\n  identity: {target: \"identity:9090\"}\n  dictionary: {target: \"dictionary:9090\"}\n" + string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	dial := func(context.Context, string, routes.Upstream) (grpc.ClientConnInterface, error) {
		t.Fatal("a descriptor set must not need the upstream")
		return nil, nil
	}
	px, err := New(tbl, dial)
	if err != nil {
		t.Fatal(err)
	}
	if err := px.Check(context.Background()); err != nil {
		t.Fatalf("descriptors.binpb is stale, run `make descriptors`: %v", err)
	}
}
