// Package proxy turns a JSON request into a unary gRPC call on an upstream and the reply back
// into JSON, without generated stubs: the message types come from a descriptor set file or from
// the upstream's reflection service.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Dialer opens (once) the connection of an upstream.
type Dialer func(ctx context.Context, name string, u routes.Upstream) (grpc.ClientConnInterface, error)

type method struct {
	full    string
	in, out protoreflect.MessageDescriptor
	at      time.Time
}

// Proxy resolves routes to methods and invokes them.
type Proxy struct {
	table *routes.Table
	files *protoregistry.Files // from the descriptor set, nil to use reflection
	dial  Dialer
	ttl   time.Duration
	// serviceToken, when set, authenticates reflection calls (audience of the upstream).
	serviceToken func(ctx context.Context, audience string) (string, error)
	now          func() time.Time

	mu      sync.Mutex
	conns   map[string]grpc.ClientConnInterface
	methods map[string]*method
}

// New builds a proxy for the table. dial is called at most once per upstream.
func New(t *routes.Table, dial Dialer) (*Proxy, error) {
	p := &Proxy{
		table: t, dial: dial, ttl: 10 * time.Minute, now: time.Now,
		conns: map[string]grpc.ClientConnInterface{}, methods: map[string]*method{},
	}
	switch {
	case t.Files != nil:
		p.files = t.Files
	case t.Descriptors != "":
		var err error
		if p.files, err = routes.LoadDescriptors(t.Descriptors); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// SetServiceToken sets the source of the token that authenticates reflection calls.
func (p *Proxy) SetServiceToken(f func(ctx context.Context, audience string) (string, error)) {
	p.serviceToken = f
}

// Check resolves every route; with a descriptor set it fails at start-up on a typo, with
// reflection it only reports what cannot be resolved yet.
func (p *Proxy) Check(ctx context.Context) error {
	var errs []error
	for _, r := range p.table.Routes {
		if _, err := p.resolve(ctx, r); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", r.Method, r.Path, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Proxy) conn(ctx context.Context, name string) (grpc.ClientConnInterface, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.conns[name]; ok {
		return c, nil
	}
	c, err := p.dial(ctx, name, p.table.Upstreams[name])
	if err != nil {
		return nil, err
	}
	p.conns[name] = c
	return c, nil
}

func (p *Proxy) resolve(ctx context.Context, r routes.Route) (*method, error) {
	key := fmt.Sprintf("%s|%s|%t", r.Upstream, r.GRPC, r.Stream) // the same method may be routed with and without stream
	p.mu.Lock()
	m := p.methods[key]
	p.mu.Unlock()
	if m != nil && p.now().Sub(m.at) < p.ttl {
		return m, nil
	}

	var md protoreflect.MethodDescriptor
	var err error
	if p.files != nil {
		md, err = p.fromFiles(r)
	} else {
		md, err = p.fromReflection(ctx, r)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case md.IsStreamingClient():
		return nil, errors.New("client-streaming methods are not supported")
	case md.IsStreamingServer() && !r.Stream:
		return nil, errors.New("a server-streaming method needs stream: true on its route")
	case !md.IsStreamingServer() && r.Stream:
		return nil, errors.New("stream: true needs a server-streaming method")
	}
	m = &method{full: "/" + r.Service + "/" + r.RPC, in: md.Input(), out: md.Output(), at: p.now()}
	p.mu.Lock()
	p.methods[key] = m
	p.mu.Unlock()
	return m, nil
}

func (p *Proxy) fromFiles(r routes.Route) (protoreflect.MethodDescriptor, error) {
	d, err := p.files.FindDescriptorByName(protoreflect.FullName(r.Service))
	if err != nil {
		return nil, fmt.Errorf("service %s not in the descriptor set", r.Service)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%s is not a service", r.Service)
	}
	md := sd.Methods().ByName(protoreflect.Name(r.RPC))
	if md == nil {
		return nil, fmt.Errorf("method %s not found on %s", r.RPC, r.Service)
	}
	return md, nil
}

func (p *Proxy) fromReflection(ctx context.Context, r routes.Route) (protoreflect.MethodDescriptor, error) {
	cc, err := p.conn(ctx, r.Upstream)
	if err != nil {
		return nil, err
	}
	conn, ok := cc.(*grpc.ClientConn)
	if !ok {
		return nil, errors.New("reflection needs a *grpc.ClientConn")
	}
	// The upstream protects its reflection service like any other: use a token of our own for
	// its audience. A fresh client per resolution keeps the token from outliving its expiry.
	if p.serviceToken != nil {
		tok, err := p.serviceToken(ctx, r.Audience)
		if err != nil {
			return nil, fmt.Errorf("service token for reflection on %s: %w", r.Upstream, err)
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
	}
	rc := grpcreflect.NewClientAuto(ctx, conn)
	defer rc.Reset()
	sd, err := rc.ResolveService(r.Service)
	if err != nil {
		return nil, fmt.Errorf("reflection on %s: %w", r.Upstream, err)
	}
	m := sd.FindMethodByName(r.RPC)
	if m == nil {
		return nil, fmt.Errorf("method %s not found on %s", r.RPC, r.Service)
	}
	return m.UnwrapMethod(), nil
}

// Call invokes the route with the JSON request (empty means {}) and returns the JSON reply.
// token is sent as the bearer of the call.
func (p *Proxy) Call(ctx context.Context, r routes.Route, body []byte, token string) ([]byte, error) {
	m, err := p.resolve(ctx, r)
	if err != nil {
		return nil, &Error{Kind: KindUnavailable, Err: err}
	}
	in := dynamicpb.NewMessage(m.in)
	if len(body) == 0 {
		body = []byte("{}")
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, in); err != nil {
		return nil, &Error{Kind: KindBadRequest, Err: err}
	}
	cc, err := p.conn(ctx, r.Upstream)
	if err != nil {
		return nil, &Error{Kind: KindUnavailable, Err: err}
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if r.Timeout > 0 { // the gRPC client only adds its default deadline when there is none
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	out := dynamicpb.NewMessage(m.out)
	if err := cc.Invoke(ctx, m.full, in, out); err != nil {
		return nil, err
	}
	return protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(out)
}

// CallStream invokes a server-streaming route (stream: true) with the JSON request and passes every reply
// message to fn as it arrives; an error of fn ends the call and is returned. The upstream stream is cancelled when
// ctx ends (the client went away) or fn fails.
func (p *Proxy) CallStream(ctx context.Context, r routes.Route, body []byte, token string, fn func(*dynamicpb.Message) error) error {
	m, err := p.resolve(ctx, r)
	if err != nil {
		return &Error{Kind: KindUnavailable, Err: err}
	}
	in := dynamicpb.NewMessage(m.in)
	if len(body) == 0 {
		body = []byte("{}")
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(body, in); err != nil {
		return &Error{Kind: KindBadRequest, Err: err}
	}
	cc, err := p.conn(ctx, r.Upstream)
	if err != nil {
		return &Error{Kind: KindUnavailable, Err: err}
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if r.Timeout > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, r.Timeout)
		defer stop()
	}
	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, m.full)
	if err != nil {
		return err
	}
	if err := stream.SendMsg(in); err != nil {
		return err
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	for {
		out := dynamicpb.NewMessage(m.out)
		if err := stream.RecvMsg(out); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := fn(out); err != nil {
			return err
		}
	}
}

// Close releases the proxy; the connections belong to the Dialer.
func (p *Proxy) Close() {}

// Kind classifies errors that did not come from the upstream.
type Kind int

const (
	KindBadRequest Kind = iota
	KindUnavailable
)

// Error is a failure of gatekeeper itself (bad JSON, upstream not resolvable).
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }
