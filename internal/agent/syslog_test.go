package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func logSourceFixture(t *testing.T, network string) syslogdata.Source {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return syslogdata.Source{ID: "firewall", Name: "边界设备", NetworkDomain: "edge", Listen: address, Transport: network, Format: "rfc5424", AllowedPeers: []string{"127.0.0.1/32"}, AcceptUnauthenticated: true, AcceptDatagramLoss: network == "udp", MaxMessageBytes: 1024, MaxConnections: 2, MaxEventsPerSecond: 100}
}
func logInput(source syslogdata.Source) SyslogInput {
	return SyslogInput{Binding: source.Binding(), ObservedAt: time.Now().UTC(), Peer: syslogdata.Peer{IP: "127.0.0.1", Port: 34000}, Raw: []byte("<13>1 2026-10-21T00:00:00Z device app 1 id - 边界日志")}
}
func logServiceFixture(t *testing.T, w *WAL, source syslogdata.Source) *SyslogService {
	t.Helper()
	raw, _ := json.Marshal(syslogdata.File{SchemaVersion: "syslog.sources.v1", Sources: []syslogdata.Source{source}})
	path := filepath.Join(t.TempDir(), "sources.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	service, err := NewSyslogService(w, path)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func waitLogHealth(t *testing.T, s *SyslogService, predicate func(syslogdata.Health) bool) syslogdata.Health {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h := s.Health()[0]
		if !h.Valid() {
			t.Fatalf("健康状态不合法: %+v", h)
		}
		if predicate(h) {
			return h
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("日志状态未到达", s.Health())
	return syslogdata.Health{}
}
func TestSyslogDurableIdentityQuotaAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	w, err := OpenWAL(path, "tenant_logs", "sensor_logs", "registration_logs", 16384)
	if err != nil {
		t.Fatal(err)
	}
	source := logSourceFixture(t, "tcp")
	input := logInput(source)
	if w.AppendSyslogBatch(nil) == nil {
		t.Fatal("空提交未拒绝")
	}
	invalid := input
	invalid.Binding.SourceID = ""
	if w.AppendSyslogBatch([]SyslogInput{input, invalid}) == nil {
		t.Fatal("不合法批次未拒绝")
	}
	count, _, _ := w.Stats()
	if count != 0 {
		t.Fatal("事务未整体回滚")
	}
	if err := w.AppendSyslogBatch([]SyslogInput{input, input}); err != nil {
		t.Fatal(err)
	}
	first, err := w.Next("logs")
	if err != nil || len(first.Records) != 2 || first.RouteToken != "" {
		t.Fatal("离线队列不正确", err)
	}
	if first.Records[0].EventId == first.Records[1].EventId || first.Records[0].SourceSequence != 1 || first.Records[1].SourceSequence != 2 {
		t.Fatal("同文日志被按内容去重")
	}
	first.RouteToken = strings.Repeat("1", 64)
	contract.Seal(first)
	if err := contract.Validate(w.TenantID, w.SensorID, w.RegistrationID, first); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(){func() { first.Records[0].SourceId = "forged" }, func() { first.Records[0].SourceSequence = 7 }, func() { first.Records[0].SourceOffset = 1 }, func() { first.Records[0].EventType = "alert" }, func() { first.Records[0].RawSha256 = []byte("bad") }} {
		saved, _ := w.Next("logs")
		first = saved
		first.RouteToken = strings.Repeat("1", 64)
		mutate()
		contract.Seal(first)
		if contract.Validate(w.TenantID, w.SensorID, w.RegistrationID, first) == nil {
			t.Fatal("伪造来源通过数据契约")
		}
	}
	first, _ = w.Next("logs")
	if err := w.BindSyslogRoute(first, strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Next("meta"); err == nil {
		t.Fatal("元信息被当作上传流")
	}
	epoch := w.Epoch
	w.Close()
	w, err = OpenWAL(path, "tenant_logs", "sensor_logs", "registration_logs", 16384)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	replay, _ := w.Next("logs")
	replay.RouteToken = strings.Repeat("1", 64)
	contract.Seal(replay)
	if replay.BatchId != first.BatchId || w.Epoch != epoch {
		t.Fatal("重启丢失重传身份")
	}
	bad := acceptedBatch(replay)
	bad.BatchSha256 = []byte("bad")
	if w.Confirm(replay, bad) == nil {
		t.Fatal("错误确认释放日志")
	}
	if err = w.Confirm(replay, acceptedBatch(replay)); err != nil {
		t.Fatal(err)
	}
	if err = w.Confirm(replay, acceptedBatch(replay)); err != nil {
		t.Fatal("重复确认不是幂等", err)
	}
	count, used, err := w.Stats()
	if err != nil || count != 0 || used != 0 {
		t.Fatal("容量没有回收")
	}
	for {
		err = w.AppendSyslogBatch([]SyslogInput{input})
		if err != nil {
			break
		}
	}
	if !errors.Is(err, ErrWALFull) {
		t.Fatal("日志配额未限制")
	}
	_, used, _ = w.Stats()
	if used > w.MaxBytes/4 {
		t.Fatal("日志挤占告警空间")
	}
	full, _ := w.Next("logs")
	if err := w.BindSyslogRoute(full, strings.Repeat("3", 64)); err != nil {
		t.Fatal("路由预留未能避免满队列阻塞", err)
	}
	if w.BindSyslogRoute(full, strings.Repeat("4", 64)) == nil || w.BindSyslogRoute(nil, strings.Repeat("4", 64)) == nil {
		t.Fatal("已绑定路由被覆盖")
	}

	// 配额满时告警仍能占用预留空间，且原文文件检查点不被 Syslog 修改。
	if err := w.Append(Source{FileID: "eve", Generation: "generation"}, "alerts", "route_alerts", &sensorv1.EventRecord{SourceGenerationId: "generation", Payload: []byte(eveSample)}); err != nil {
		t.Fatal("日志配额阻断了告警", err)
	}
	if err := w.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("syslog/firewall/sequence"), key(^uint64(0)))
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.AppendSyslogBatch([]SyslogInput{input}); err == nil {
		t.Fatal("来源序列溢出未拒绝")
	}
}
func TestSyslogFramingRetainsMultilineAndRejectsSmuggling(t *testing.T) {
	for _, raw := range []string{"hello", "line1\nline2", "\x00\xffabc"} {
		frame := fmt.Sprintf("%d %s%d second", len(raw), raw, len("second"))
		reader := bufio.NewReader(strings.NewReader(frame))
		first, err := readSyslogFrame(reader, 1024)
		if err != nil || string(first) != raw {
			t.Fatal("长度分帧破坏原文", err)
		}
		next, err := readSyslogFrame(reader, 1024)
		if err != nil || string(next) != "second" {
			t.Fatal("连续帧未正确读取")
		}
		if _, err = readSyslogFrame(reader, 1024); err != io.EOF {
			t.Fatal("连接边界无效")
		}
	}
	for _, raw := range []string{"0 ", "01 x", "+1 x", "-1 x", " 1 x", "1000000 ", "12 short", "1", "1\nx", "a x", "99999999999 "} {
		if _, err := readSyslogFrame(bufio.NewReader(strings.NewReader(raw)), 1024); err == nil {
			t.Errorf("不合法分帧被接受 %q", raw)
		}
	}
}
func TestSyslogTCPAndUDPDurableReceive(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			w, _, _ := readerFor(t, 1<<20)
			source := logSourceFixture(t, network)
			s := logServiceFixture(t, w, source)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(3 * time.Second):
					t.Error("接收器未关闭")
				}
			}()
			waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.State == "listening" })
			if s.Run(ctx) == nil {
				t.Fatal("并发运行未拒绝")
			}
			conn, err := net.Dial(network, source.Listen)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw := []byte("<13>1 2026-10-21T00:00:00Z spoofed-tenant app 1 id - 第一行\n第二行")
			for range 2 {
				if network == "tcp" {
					_, err = fmt.Fprintf(conn, "%d %s", len(raw), raw)
				} else {
					_, err = conn.Write(raw)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			h := waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.Persisted == "2" })
			if h.Received != "2" || h.Dropped != "0" {
				t.Fatal("计数不正确")
			}
			batch, err := w.Next("logs")
			if err != nil || len(batch.Records) != 2 {
				t.Fatal("日志未持久保存")
			}
			for _, r := range batch.Records {
				v, original, err := syslogdata.DecodeRecord(r.Payload)
				if err != nil || !bytes.Equal(original, raw) || v.Binding.SourceID != "firewall" || v.Peer.IP != "127.0.0.1" {
					t.Fatal("原文或接收身份改变")
				}
			}
			if network == "tcp" {
				fmt.Fprint(conn, "03 bad")
			} else {
				conn.Write(bytes.Repeat([]byte("x"), 1025))
				conn.Write(nil)
			}
			waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.FramingErrors != "0" })
		})
	}
}
func TestSyslogReceiverFailureBoundaries(t *testing.T) {
	w, _, _ := readerFor(t, 4096)
	source := logSourceFixture(t, "tcp")
	s := logServiceFixture(t, w, source)
	if _, err := NewSyslogService(w, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("缺失配置被接受")
	}
	// 端口占用须显式不可用，不得以空目录宣称接收成功。
	listener, err := net.Listen("tcp", source.Listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.State == "unavailable" })
	listener.Close()
	waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.State == "listening" })
	conn, err := net.Dial("tcp", source.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	input := logInput(source)
	for i := 0; i < 5; i++ {
		_, err = fmt.Fprintf(conn, "%d %s", len(input.Raw), input.Raw)
		if err != nil {
			break
		}
	}
	waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.State == "degraded" })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	h := s.Health()[0]
	if h.State != "stopped" || h.Dropped == "0" {
		t.Fatal("失败状态没有保留")
	}
}

func TestSyslogReceiverRejectsUnauthorisedPeersAndExcessWork(t *testing.T) {
	w, _, _ := readerFor(t, 1<<20)
	source := logSourceFixture(t, "tcp")
	source.AllowedPeers = []string{"192.0.2.0/24"}
	s := logServiceFixture(t, w, source)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.State == "listening" })
	conn, err := net.Dial("tcp", source.Listen)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	waitLogHealth(t, s, func(h syslogdata.Health) bool { return h.Rejected == "1" })
	if _, _, valid := remotePeer(&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}); valid {
		t.Fatal("缺少端口的对端被接受")
	}
	// 有界内存入口与速率预算都在持久队列前拒绝，并记为本机已知未保存。
	source.Transport = "udp"
	source.AcceptDatagramLoss = true
	source.AllowedPeers = []string{"127.0.0.1/32"}
	source.MaxEventsPerSecond = 1
	udp := logServiceFixture(t, w, source)
	v := udp.sources[0]
	peer := syslogdata.Peer{IP: "127.0.0.1", Port: 34001}
	raw := []byte("test")
	if udp.submit(ctx, v, peer, raw, true) != nil {
		t.Fatal("首个报文被拒绝")
	}
	if udp.submit(ctx, v, peer, raw, true) == nil {
		t.Fatal("来源速率预算未执行")
	}
	v.limiter.SetLimit(10000)
	v.limiter.SetBurst(10000)
	for len(udp.queue) < cap(udp.queue) {
		v.limiter = rate.NewLimiter(rate.Inf, 10000)
		if err := udp.submit(ctx, v, peer, raw, true); err != nil {
			t.Fatal(err)
		}
	}
	if !errors.Is(udp.submit(ctx, v, peer, raw, true), ErrWALFull) {
		t.Fatal("内存入口容量未限制")
	}
}
func TestSyslogTLSPrivateMaterialValidation(t *testing.T) {
	w, _, _ := readerFor(t, 1<<20)
	dir := t.TempDir()
	source := logSourceFixture(t, "tls")
	source.AcceptUnauthenticated = false
	source.TLS = syslogdata.TLSFiles{CertificateFile: filepath.Join(dir, "cert"), PrivateKeyFile: filepath.Join(dir, "key"), ClientCAFile: filepath.Join(dir, "ca"), ClientFingerprints: []string{strings.Repeat("a", 64)}}
	raw, _ := json.Marshal(syslogdata.File{SchemaVersion: "syslog.sources.v1", Sources: []syslogdata.Source{source}})
	path := filepath.Join(dir, "source.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, next := range []string{"cert", "key", "ca", "all"} {
		if _, err := NewSyslogService(w, path); err == nil {
			t.Fatal("缺失或损坏的 TLS 材料被接受")
		}
		if next != "all" {
			if err := os.WriteFile(filepath.Join(dir, next), []byte("not a certificate"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type syslogRouteClient struct {
	sensorv1.SensorServiceClient
	route func(context.Context, *sensorv1.RouteRequest) (*sensorv1.Route, error)
}

func (c syslogRouteClient) GetRoute(ctx context.Context, r *sensorv1.RouteRequest, _ ...grpc.CallOption) (*sensorv1.Route, error) {
	return c.route(ctx, r)
}
func TestSyslogFirstRouteSurvivesUnknownAckAndNewDayRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	w, err := OpenWAL(path, "tenant_logs", "sensor_logs", "registration_logs", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { w.Close() }()
	input := logInput(logSourceFixture(t, "tcp"))
	if err = w.AppendSyslogBatch([]SyslogInput{input}); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("1", 64)
	firstSeen := make(chan *sensorv1.EventBatch, 1)
	peer := fixtureStreamClient(t, &streamFixture{upload: func(stream grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error {
		batch, err := stream.Recv()
		if err != nil {
			return err
		}
		firstSeen <- batch
		return status.Error(codes.Unavailable, "确认丢失")
	}})
	client := syslogRouteClient{SensorServiceClient: peer, route: func(context.Context, *sensorv1.RouteRequest) (*sensorv1.Route, error) {
		return &sensorv1.Route{Token: token, TenantId: w.TenantID, StreamId: "logs", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}, nil
	}}
	run, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { upload(run, client, w, "logs"); close(done) }()
	var first *sensorv1.EventBatch
	select {
	case first = <-firstSeen:
	case <-time.After(3 * time.Second):
		cancel()
		<-done
		t.Fatal("首次上传没有发送")
	}
	cancel()
	<-done
	if err := contract.Validate(w.TenantID, w.SensorID, w.RegistrationID, first); err != nil {
		t.Fatal(err)
	}
	persisted, err := w.Next("logs")
	if err != nil || persisted.RouteToken != token {
		t.Fatal("路由未在发送前持久化")
	}
	w.Close()
	w, err = OpenWAL(path, "tenant_logs", "sensor_logs", "registration_logs", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// 后续平台日期已变更时，已冻结的原路由不能被新路由替换。
	var routeCalls atomic.Int32
	peer = fixtureStreamClient(t, &streamFixture{upload: func(stream grpc.BidiStreamingServer[sensorv1.EventBatch, sensorv1.IngestAck]) error {
		batch, err := stream.Recv()
		if err != nil {
			return err
		}
		if batch.RouteToken != token || batch.BatchId != first.BatchId {
			t.Error("未知确认重试改变了分区或批次")
		}
		return stream.Send(acceptedBatch(batch))
	}})
	client = syslogRouteClient{SensorServiceClient: peer, route: func(context.Context, *sensorv1.RouteRequest) (*sensorv1.Route, error) {
		routeCalls.Add(1)
		return &sensorv1.Route{Token: strings.Repeat("2", 64), TenantId: w.TenantID, StreamId: "logs", ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}, nil
	}}
	run, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { upload(run, client, w, "logs"); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		count, _, _ := w.Stats()
		if count == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	count, bytes, err := w.Stats()
	if err != nil || count != 0 || bytes != 0 || routeCalls.Load() != 0 {
		t.Fatal("原路由没有复用或精确确认未释放队列", count, bytes)
	}
}
