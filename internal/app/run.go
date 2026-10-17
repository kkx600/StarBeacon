// Package app 组装运行角色，业务包不负责环境加载和操作系统信号。
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/agent"
	"github.com/kkx600/StarBeacon/internal/buildinfo"
	"github.com/kkx600/StarBeacon/internal/bus"
	"github.com/kkx600/StarBeacon/internal/config"
	"github.com/kkx600/StarBeacon/internal/control"
	"github.com/kkx600/StarBeacon/internal/httpapi"
	"github.com/kkx600/StarBeacon/internal/ingest"
	"github.com/kkx600/StarBeacon/internal/jobs"
	"github.com/kkx600/StarBeacon/internal/mcpserver"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/packetarchive"
	"github.com/kkx600/StarBeacon/internal/platform"
	"github.com/kkx600/StarBeacon/internal/probepki"
	"github.com/kkx600/StarBeacon/internal/replay"
	"github.com/kkx600/StarBeacon/internal/secrets"
	"github.com/kkx600/StarBeacon/internal/store"
	"github.com/kkx600/StarBeacon/internal/telemetry"
	"github.com/kkx600/StarBeacon/internal/transport"
	"github.com/kkx600/StarBeacon/internal/worker"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
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
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(t)), grpc.MaxRecvMsgSize(4*1024*1024), grpc.MaxConcurrentStreams(16), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: 5 * time.Minute, MaxConnectionAgeGrace: 30 * time.Second}))
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
	var vault *secrets.Vault
	if c.CredentialKey != "" {
		var err error
		vault, err = secrets.New(c.CredentialKey)
		if err != nil {
			return err
		}
	}
	networks, e := outbound.ParseNetworks(c.OutboundNetworks)
	if e != nil {
		return e
	}
	roots, e := outbound.LoadRoots(c.OutboundCA)
	if e != nil {
		return e
	}
	policy := outbound.Policy{PrivateNetworks: networks, Development: c.Mode == "development", Roots: roots}
	mcpConfig := mcpserver.Config{Origin: c.AllowedOrigin, Issuer: c.MCPIssuer, IntrospectionURL: c.MCPIntrospectionURL, ClientID: c.MCPClientID, ClientSecret: c.MCPClientSecret}
	if role == "platform" && c.MCPIssuer != "" {
		if err := mcpConfig.Validate(policy); err != nil {
			return err
		}
	}
	// 本地签名、存储与地址配置先核对；远端连接延迟不能掩盖本地配置错误。
	var signer ed25519.PrivateKey
	var samples replay.Storage
	var packets packetarchive.ObjectStorage
	var redisOptions *redis.Options
	packetStaging := filepath.Join(c.PacketDir, "validation")
	if role == "platform" {
		signer, e = control.PrivateKey(c.CommandSigningKey)
		if e != nil {
			return e
		}
	}
	if role == "platform" {
		redisOptions, e = redis.ParseURL(c.RedisURL)
		if e != nil {
			return e
		}
		if c.ReplayBackend != "" {
			local, e := replay.NewLocal(c.ReplayDir, c.ReplayBytes)
			if e != nil {
				return e
			}
			samples = local
			if c.ReplayBackend == "s3" {
				samples, e = replay.NewS3(c.ReplayS3Endpoint, c.ReplayS3AccessKey, c.ReplayS3SecretKey, c.ReplayS3Bucket, c.ReplayS3Secure, local)
				if e != nil {
					return e
				}
			}
		}
		if c.PacketBackend != "" {
			if e = os.MkdirAll(packetStaging, 0700); e != nil {
				return e
			}
			if c.PacketBackend == "s3" {
				packets, e = packetarchive.NewS3Objects(c.ReplayS3Endpoint, c.ReplayS3AccessKey, c.ReplayS3SecretKey, c.ReplayS3Bucket, c.ReplayS3Secure)
			} else {
				packets, e = packetarchive.NewLocalObjects(filepath.Join(c.PacketDir, "objects"))
			}
			if e != nil {
				return e
			}
		}
	}
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var db *store.Postgres
	var queue *bus.Bus
	var es *store.Elasticsearch
	var redisClient *redis.Client
	if role == "platform" || role == "ingest" || role == "worker" {
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
		redisClient = redis.NewClient(redisOptions)
		defer redisClient.Close()
		if e = redisClient.Ping(startup).Err(); e != nil {
			return e
		}
		auth := httpapi.NewAuth(db, redisClient, c.AllowedOrigin, c.CookieName, c.Mode == "production")
		wakeup := &control.Wakeup{}
		api := &platform.API{Wakeup: wakeup, DB: db, ES: es, Redis: redisClient, Auth: auth, Signer: signer, Samples: samples, SampleQuota: c.ReplayBytes, Vault: vault, Outbound: policy, Packets: packets, PacketStaging: packetStaging}
		if c.ProbeCAURL != "" {
			api.Authority, e = probepki.NewStep(probepki.StepConfig{URL: c.ProbeCAURL, RootFile: c.ProbeCARoot, Provisioner: c.ProbeCAProvisioner, JWKFile: c.ProbeCAJWK, Lifetime: c.ProbeCertificateLifetime})
			if e != nil {
				return e
			}
		}

		if packets != nil {
			group.Go(func() error {
				ticker := time.NewTicker(time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-run.Done():
						return nil
					case <-ticker.C:
						call, cancel := context.WithTimeout(run, 20*time.Second)
						err := db.SweepPacketArchives(call, packets)
						cancel()
						if err != nil && run.Err() == nil {
							slog.Warn("原包到期回收未完成")
						}
					}
				}
			})
		}
		group.Go(func() error {
			timer := time.NewTicker(time.Minute)
			defer timer.Stop()
			for {
				select {
				case <-run.Done():
					return nil
				case <-timer.C:
					started := time.Now()
					report, err := db.SweepHistory(run)
					telemetry.HistoryDuration.Observe(time.Since(started).Seconds())
					for table, count := range report.ByTable {
						if count > 0 {
							telemetry.HistoryDeleted.WithLabelValues(table).Add(float64(count))
						}
					}
					state := "succeeded"
					if err != nil {
						state = "failed"
						if run.Err() == nil {
							slog.Warn("历史记录清理未完成")
						}
					}
					telemetry.HistoryRuns.WithLabelValues(state).Inc()
				}
			}
		})
		{
			analysisQueue, err := jobs.NewAnalysisWithTriage(db, vault, policy, es, api.Overview)
			if err != nil {
				return err
			}
			var available atomic.Bool
			api.Jobs, api.JobsReady = analysisQueue, available.Load
			group.Go(func() error {
				// 平台生命周期统一发起取消，避免将父级截止时间直接传入队列监听与重连循环。
				queueContext, queueStop := context.WithCancel(context.WithoutCancel(run))
				defer queueStop()
				if err := analysisQueue.Start(queueContext); err != nil {
					slog.Warn("报告计划与模型分析执行服务不可用，平台统计与采集继续运行")
					return nil
				}
				available.Store(true)
				<-run.Done()
				available.Store(false)
				stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := analysisQueue.StopAndCancel(stop); err != nil {
					slog.Warn("模型分析执行服务退出未完成")
				}
				return nil
			})
		}
		// 队列与就绪状态完成绑定后才启动读取 API 配置的持续轮询。
		group.Go(func() error {
			timer := time.NewTicker(time.Second)
			defer timer.Stop()
			after := ""
			for {
				select {
				case <-run.Done():
					return nil
				case <-timer.C:
					call, cancel := context.WithTimeout(run, 10*time.Second)
					next, _, err := api.SweepRuleSync(call, after)
					cancel()
					after = next
					if err != nil && run.Err() == nil {
						slog.Warn("规则同步阶段核对未完成，未确认任务保持原状态")
					}
				}
			}
		})
		group.Go(func() error {
			timer := time.NewTicker(time.Second)
			defer timer.Stop()
			after := ""
			for {
				select {
				case <-run.Done():
					return nil
				case <-timer.C:
					call, cancel := context.WithTimeout(run, 10*time.Second)
					next, _, err := api.SweepContinuousDecisions(call, after)
					cancel()
					after = next
					if err != nil && run.Err() == nil {
						slog.Warn("持续决策部分材料核对未完成，未确认任务不执行")
					}
				}
			}
		})
		if samples != nil {
			group.Go(func() error {
				timer := time.NewTicker(time.Minute)
				defer timer.Stop()
				for {
					select {
					case <-run.Done():
						return nil
					case <-timer.C:
						ctx, cancel := context.WithTimeout(run, 20*time.Second)
						e := db.SweepSamples(ctx, samples)
						if object, ok := samples.(*replay.S3Storage); ok && e == nil {
							e = object.Staging.PurgeOrphans(ctx, nil)
						}
						cancel()
						if e != nil && run.Err() == nil {
							slog.Warn("重放样本清理未完成")
						}
					}
				}
			})
		}
		handler = api.Handler()
		if c.MCPIssuer != "" {
			service, err := mcpserver.New(mcpConfig, api, policy)
			if err != nil {
				return err
			}
			defer service.Close()
			api.MCP = service
			m.Handle("/mcp", service.Handler)
			m.Handle("GET /.well-known/oauth-protected-resource/mcp", service.Metadata)
			m.Handle("/", api.Handler())
			handler = m
		}
		group.Go(func() error {
			return serveGRPC(run, c, &ingest.Server{DB: db, ControlOnly: true, TasksEnabled: len(signer) > 0, Wakeup: wakeup, Samples: samples, Packets: packets, PacketStaging: packetStaging, PacketQuota: c.PacketStorageBytes, Authority: api.Authority})
		})
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
			if e := db.Pool.Ping(ctx); e != nil {
				return e
			}
			if e := queue.NC.FlushWithContext(ctx); e != nil {
				return e
			}
			return es.Ping(ctx)
		})
		indexer := &worker.Indexer{Bus: queue, ES: es, DB: db}
		group.Go(func() error { return indexer.Run(run) })
		if vault != nil {
			notifier := &worker.Notifier{Bus: queue, DB: db, Vault: vault, Sender: notify.Sender{Policy: policy}}
			group.Go(func() error { return notifier.Run(run) })
		}
	default:
		return fmt.Errorf("未知运行角色")
	}
	group.Go(func() error {
		cert, key := "", ""
		if c.Mode == "production" {
			cert, key = c.TLSCert, c.TLSKey
			if c.HTTPTLSCert != "" {
				cert, key = c.HTTPTLSCert, c.HTTPTLSKey
			}
		}
		return httpapi.ServeWithClientIP(run, c.HTTPAddr, handler, cert, key, c.HTTPClientIPs)
	})
	slog.Info("服务启动", "role", role, "http", c.HTTPAddr, "version", buildinfo.Version)
	return group.Wait()
}
