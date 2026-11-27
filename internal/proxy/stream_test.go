package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gocommon/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// chunkFiles describes test.v1.Files/Get(Request{token}) returns (stream Chunk{filename, size, data}) and
// test.v1.Files/Put (a client-streaming method, which the proxy refuses).
func chunkFiles(t *testing.T) *protoregistry.Files {
	t.Helper()
	str, i64, byt := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_INT64, descriptorpb.FieldDescriptorProto_TYPE_BYTES
	field := func(name string, n int32, typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: typ.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()}
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("test.proto"), Package: proto.String("test.v1"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Request"), Field: []*descriptorpb.FieldDescriptorProto{field("token", 1, str)}},
			{Name: proto.String("Chunk"), Field: []*descriptorpb.FieldDescriptorProto{field("filename", 1, str), field("size", 2, i64), field("data", 3, byt)}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Files"), Method: []*descriptorpb.MethodDescriptorProto{
			{Name: proto.String("Get"), InputType: proto.String(".test.v1.Request"), OutputType: proto.String(".test.v1.Chunk"), ServerStreaming: proto.Bool(true)},
			{Name: proto.String("Put"), InputType: proto.String(".test.v1.Request"), OutputType: proto.String(".test.v1.Chunk"), ClientStreaming: proto.Bool(true), ServerStreaming: proto.Bool(true)},
			{Name: proto.String("One"), InputType: proto.String(".test.v1.Request"), OutputType: proto.String(".test.v1.Chunk")},
		}}},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	files := &protoregistry.Files{}
	if err := files.RegisterFile(fd); err != nil {
		t.Fatal(err)
	}
	return files
}

// streamProxy serves test.v1.Files/Get with send and returns a proxy for it (the routes of the test below).
func streamProxy(t *testing.T, send func(ctx context.Context, token string, out func(filename string, size int64, data []byte) error) error) (*Proxy, *routes.Table) {
	t.Helper()
	files := chunkFiles(t)
	d, _ := files.FindDescriptorByName("test.v1.Files")
	svc := d.(protoreflect.ServiceDescriptor)
	reqD, chunkD := svc.Methods().ByName("Get").Input(), svc.Methods().ByName("Get").Output()

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.v1.Files", HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{StreamName: "Get", ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
			req := dynamicpb.NewMessage(reqD)
			if err := stream.RecvMsg(req); err != nil {
				return err
			}
			token := req.Get(reqD.Fields().ByName("token")).String()
			return send(stream.Context(), token, func(filename string, size int64, data []byte) error {
				m := dynamicpb.NewMessage(chunkD)
				m.Set(chunkD.Fields().ByName("filename"), protoreflect.ValueOfString(filename))
				m.Set(chunkD.Fields().ByName("size"), protoreflect.ValueOfInt64(size))
				m.Set(chunkD.Fields().ByName("data"), protoreflect.ValueOfBytes(data))
				return stream.SendMsg(m)
			})
		}}},
	}, nil)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	tbl, err := routes.Parse([]byte(`upstreams:
  files: {target: x}
routes:
  - {http: "GET /get/{token}", grpc: test.v1.Files/Get, upstream: files, anonymous: true, download: true, stream: true}
  - {http: "GET /plain/{token}", grpc: test.v1.Files/Get, upstream: files, anonymous: true, download: true}
  - {http: GET /put, grpc: test.v1.Files/Put, upstream: files, download: true, stream: true}
  - {http: GET /one, grpc: test.v1.Files/One, upstream: files, download: true, stream: true}
`), routes.RuleMap{"test.v1.Files/Put": grpcserver.PublicRule, "test.v1.Files/One": grpcserver.PublicRule})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(tbl, func(context.Context, string, routes.Upstream) (grpc.ClientConnInterface, error) {
		return grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	})
	if err != nil {
		t.Fatal(err)
	}
	p.files = files
	return p, tbl
}

func TestCallStreamDeliversEveryChunkInOrder(t *testing.T) {
	var gotAuth string
	p, tbl := streamProxy(t, func(ctx context.Context, token string, out func(string, int64, []byte) error) error {
		md, _ := metadata.FromIncomingContext(ctx)
		gotAuth = md.Get("authorization")[0]
		if err := out(token+".apkg", 6, []byte("ab")); err != nil {
			return err
		}
		for _, c := range []string{"cd", "ef"} {
			if err := out("", 0, []byte(c)); err != nil {
				return err
			}
		}
		return nil
	})
	var names []string
	var data string
	err := p.CallStream(context.Background(), tbl.Routes[0], []byte(`{"token":"abc"}`), "tok", func(m *dynamicpb.Message) error {
		f := m.Descriptor().Fields()
		names = append(names, m.Get(f.ByName("filename")).String())
		data += string(m.Get(f.ByName("data")).Bytes())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if data != "abcdef" || len(names) != 3 || names[0] != "abc.apkg" || names[1] != "" {
		t.Errorf("names %q data %q", names, data)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("authorization %q", gotAuth)
	}
}

func TestCallStreamPassesTheErrorOfTheUpstream(t *testing.T) {
	// before any message: the status of the upstream
	p, tbl := streamProxy(t, func(context.Context, string, func(string, int64, []byte) error) error {
		return status.Error(codes.NotFound, "gone")
	})
	err := p.CallStream(context.Background(), tbl.Routes[0], []byte(`{"token":"x"}`), "t", func(*dynamicpb.Message) error {
		t.Error("no message expected")
		return nil
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("want NotFound, got %v", err)
	}

	// in the middle: the messages before it arrived, then the error
	p, tbl = streamProxy(t, func(_ context.Context, _ string, out func(string, int64, []byte) error) error {
		if err := out("f", 10, []byte("12345")); err != nil {
			return err
		}
		return status.Error(codes.Internal, "disk")
	})
	n := 0
	err = p.CallStream(context.Background(), tbl.Routes[0], []byte(`{"token":"x"}`), "t", func(*dynamicpb.Message) error { n++; return nil })
	if status.Code(err) != codes.Internal || n != 1 {
		t.Errorf("got %d messages and %v", n, err)
	}
}

func TestCallStreamStopsWhenTheCallerFailsOrCancels(t *testing.T) {
	stopped := make(chan error, 2)
	p, tbl := streamProxy(t, func(ctx context.Context, _ string, out func(string, int64, []byte) error) error {
		for ctx.Err() == nil {
			if err := out("f", 1<<30, make([]byte, 1024)); err != nil {
				stopped <- err
				return err
			}
		}
		stopped <- ctx.Err()
		return ctx.Err()
	})
	// fn fails (the browser closed the connection): the upstream stream is cancelled
	boom := errors.New("client gone")
	if err := p.CallStream(context.Background(), tbl.Routes[0], []byte(`{"token":"x"}`), "t", func(*dynamicpb.Message) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("want the error of fn, got %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream kept sending after fn failed")
	}
	// the context ends
	ctx, cancel := context.WithCancel(context.Background())
	err := p.CallStream(ctx, tbl.Routes[0], []byte(`{"token":"x"}`), "t", func(*dynamicpb.Message) error { cancel(); return nil })
	if status.Code(err) != codes.Canceled {
		t.Errorf("want Canceled, got %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream kept sending after the cancel")
	}
}

func TestStreamRoutesMustMatchTheMethod(t *testing.T) {
	p, tbl := streamProxy(t, func(context.Context, string, func(string, int64, []byte) error) error { return nil })
	for i, name := range []string{"stream on a streaming method", "streaming method without stream", "client streaming", "stream on a unary method"} {
		_, err := p.resolve(context.Background(), tbl.Routes[i])
		if (i == 0) != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
