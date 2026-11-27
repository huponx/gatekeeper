package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gatekeeper/internal/appconfig"
	"github.com/huponx/gatekeeper/internal/bff"
	"github.com/huponx/gatekeeper/internal/proxy"
	"github.com/huponx/gatekeeper/internal/routes"
	"github.com/huponx/gatekeeper/internal/session"
	"github.com/huponx/gatekeeper/internal/status"
	"github.com/huponx/gocommon/config"
	"github.com/huponx/gocommon/grpcclient"
	"github.com/huponx/gocommon/healthz"
	"github.com/huponx/gocommon/httpx"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/gocommon/oidcclient"
	"github.com/huponx/gocommon/tokenexchange"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.MustLoad[appconfig.Gatekeeper]()
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	name := cfg.Service
	if name == "" || name == "app" {
		name = "gatekeeper"
	}
	log, err := logging.New(logging.Config{Level: cfg.Level, Encoding: cfg.Encoding, Service: name, Env: cfg.Env})
	if err != nil {
		panic(err)
	}
	defer logging.Sync(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	table, err := routes.Load(cfg.RoutesFile)
	if err != nil {
		log.Fatal("routes", zap.Error(err))
	}

	ropts, err := redis.ParseURL(cfg.Redis.URL())
	if err != nil {
		log.Fatal("redis url", zap.Error(err))
	}
	rdb := redis.NewClient(ropts)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatal("redis", zap.Error(err))
	}
	sessions, err := session.New(rdb, session.Config{Keys: cfg.SessionKeys, IdleTTL: cfg.SessionIdleTTL, AbsoluteTTL: cfg.SessionAbsoluteTTL})
	if err != nil {
		log.Fatal("session store", zap.Error(err))
	}

	oc, err := oidcclient.Discover(ctx, oidcclient.Config{
		Issuer: cfg.IdentityIssuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		RedirectURL: cfg.PublicURL + "/auth/callback",
	})
	if err != nil {
		log.Fatal("identity discovery", zap.Error(err))
	}
	keys, err := jwtx.NewRemoteKeySet(jwtx.RemoteKeySetConfig{URL: oc.Provider().JWKSURI})
	if err != nil {
		log.Fatal("jwks", zap.Error(err))
	}
	verifier, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: cfg.IdentityIssuer, Audience: cfg.Audience, Keys: keys})
	if err != nil {
		log.Fatal("verifier", zap.Error(err))
	}
	exch, err := tokenexchange.New(tokenexchange.Config{
		TokenURL: oc.Provider().TokenEndpoint, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
	})
	if err != nil {
		log.Fatal("token exchange", zap.Error(err))
	}

	dial := func(ctx context.Context, upName string, u routes.Upstream) (grpc.ClientConnInterface, error) {
		insecure := cfg.UpstreamInsecure
		if u.Insecure != nil {
			insecure = *u.Insecure
		}
		return grpcclient.Dial(ctx, u.Target, grpcclient.WithLogger(log), grpcclient.WithInsecure(insecure),
			grpcclient.WithMaxMsgSize(cfg.UpstreamMaxRecvBytes, 0))
	}
	px, err := proxy.New(table, dial)
	if err != nil {
		log.Fatal("proxy", zap.Error(err))
	}
	px.SetServiceToken(exch.ServiceToken)
	if err := px.Check(ctx); err != nil {
		// with a descriptor set this is a configuration error; with reflection the upstream may just not be up yet
		if table.Descriptors != "" {
			log.Fatal("routes do not match the descriptors", zap.Error(err))
		}
		log.Warn("some routes cannot be resolved yet", zap.Error(err))
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery(), httpx.Logger(log), httpx.RequestContext(), httpx.AccessLog())
	router.GET("/healthz", healthz.Live())
	router.GET("/readyz", healthz.Ready(healthz.Check{Name: "redis", Fn: func(ctx context.Context) error { return rdb.Ping(ctx).Err() }}))
	srvBFF := bff.New(bff.Config{
		PublicURL: cfg.PublicURL, Origins: cfg.Origins(), PostLoginURL: cfg.PostLoginURL, PortalURL: cfg.PortalURL, ACRValues: cfg.DefaultACR,
		Secure: !cfg.IsLocal() || len(cfg.PublicURL) > 8 && cfg.PublicURL[:8] == "https://",
	}, oc, verifier, sessions, px, exch, table, log)
	if cfg.ArgoCDURL != "" {
		st, err := status.New(status.Config{URL: cfg.ArgoCDURL, Token: cfg.ArgoCDToken, Project: cfg.ArgoCDProject})
		if err != nil {
			log.Fatal("system status", zap.Error(err))
		}
		srvBFF.SetStatus(st)
	}
	srvBFF.Routes(router)

	srv := &http.Server{
		Addr: cfg.Addr(), Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("gatekeeper listening", zap.String("addr", cfg.Addr()), zap.String("public_url", cfg.PublicURL), zap.Int("routes", len(table.Routes)))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		log.Error("serve", zap.Error(err))
	}
	shut, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(shut)
	px.Close()
}
