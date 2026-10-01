// Package app 组装运行角色，业务包不负责环境加载和操作系统信号。
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/buildinfo"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Main(role string) {
	version := flag.Bool("version", false, "显示构建版本")
	flag.Parse()
	if *version {
		fmt.Printf("StarBeacon %s %s (%s)\n", role, buildinfo.Version, buildinfo.Commit)
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	c, e := config.Load(role)
	if e != nil {
		slog.Error("配置不合法", "reason", e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = Run(ctx, role, c); e != nil && !errors.Is(e, context.Canceled) {
		slog.Error("运行进程退出", "role", role, "reason", e)
		os.Exit(1)
	}
}
func serveGRPC(ctx context.Context, c config.Config, service *ingest.Server) error {
	t, e := transport.TLS(c.TLSCA, c.TLSCert, c.TLSKey, true)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", c.GRPCAddr)
	if e != nil {
		return e
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(t)), grpc.MaxRecvMsgSize(4*1024*1024), grpc.MaxConcurrentStreams(16))
	sensorv1.RegisterSensorServiceServer(s, service)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stopped := make(chan struct{})
			go func() { s.GracefulStop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				s.Stop()
			}
		case <-done:
		}
	}()
	e = s.Serve(listener)
	close(done)
	if errors.Is(e, grpc.ErrServerStopped) {
		return nil
	}
	return e
}
func Run(ctx context.Context, role string, c config.Config) error {
	if role == "agent" {
		return agent.Run(ctx, c)
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var db *store.Postgres
	var queue *bus.Bus
	var es *store.Elasticsearch
	var redisClient *redis.Client
	var e error
	if role == "platform" || role == "ingest" {
		db, e = store.Open(startup, c.DatabaseURL)
		if e != nil {
			return e
		}
		defer db.Close()
		if e = db.VerifyRuntimeRole(startup); e != nil {
			return e
		}
	}
	if role == "ingest" || role == "worker" {
		queue, e = bus.OpenNamespace(startup, c.NATSURL, c.NATSNamespace)
		if e != nil {
			return e
		}
		defer queue.Close()
		if e = queue.Ensure(startup, c.Replicas, c.StreamBytes); e != nil {
			return e
		}
	}
	if role == "platform" || role == "worker" {
		es, e = store.OpenES(c.ESURL, c.ESAPIKey)
		if e != nil {
			return e
		}
		if e = es.Ping(startup); e != nil {
			return e
		}
	}
	group, run := errgroup.WithContext(ctx)
	m := http.NewServeMux()
	var handler http.Handler = m
	switch role {
	case "platform":
		options, e := redis.ParseURL(c.RedisURL)
		if e != nil {
			return e
		}
		redisClient = redis.NewClient(options)
		defer redisClient.Close()
		if e = redisClient.Ping(startup).Err(); e != nil {
			return e
		}
		auth := httpapi.NewAuth(db, redisClient, c.AllowedOrigin, c.CookieName, c.Mode == "production")
		api := &platform.API{DB: db, ES: es, Redis: redisClient, Auth: auth}
		handler = api.Handler()
		group.Go(func() error { return serveGRPC(run, c, &ingest.Server{DB: db, ControlOnly: true}) })
	case "ingest":
		httpapi.Health(m, func(ctx context.Context) error {
			if e := db.Pool.Ping(ctx); e != nil {
				return e
			}
			return queue.NC.FlushWithContext(ctx)
		})
		group.Go(func() error { return serveGRPC(run, c, &ingest.Server{DB: db, Bus: queue}) })
	case "worker":
		httpapi.Health(m, func(ctx context.Context) error {
			if e := queue.NC.FlushWithContext(ctx); e != nil {
				return e
			}
			return es.Ping(ctx)
		})
		indexer := &worker.Indexer{Bus: queue, ES: es}
		group.Go(func() error { return indexer.Run(run) })
	default:
		return fmt.Errorf("未知运行角色")
	}
	group.Go(func() error {
		cert, key := "", ""
		if c.Mode == "production" {
			cert, key = c.TLSCert, c.TLSKey
		}
		return httpapi.Serve(run, c.HTTPAddr, handler, cert, key)
	})
	slog.Info("服务启动", "role", role, "http", c.HTTPAddr, "version", buildinfo.Version)
	return group.Wait()
}
