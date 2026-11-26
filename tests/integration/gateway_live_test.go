//go:build integration && gatewayintegration && linux

package integration

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/gatewayblock"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/watchlist"
	"golang.org/x/sys/unix"
)

type httpGatewayPeer struct {
	input  io.WriteCloser
	output *json.Decoder
	ports  [2]uint16
}

func startGatewayHTTPPeer(t *testing.T, ctx context.Context, pid int, script, destination string) *httpGatewayPeer {
	t.Helper()
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "-t", strconv.Itoa(pid), "-n", "--",
		"/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/python3", "-I", script, "client", destination)
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	require(t, err)
	output, err := cmd.StdoutPipe()
	require(t, err)
	require(t, cmd.Start())
	t.Cleanup(func() {
		_ = input.Close()
		_ = cmd.Wait()
	})
	peer := &httpGatewayPeer{input: input, output: json.NewDecoder(output)}
	require(t, peer.output.Decode(&peer.ports))
	if peer.ports[0] == 0 || peer.ports[1] == 0 || peer.ports[0] == peer.ports[1] {
		t.Fatal("HTTP 夹具没有建立两条独立连接")
	}
	return peer
}

func (p *httpGatewayPeer) exchange(t *testing.T, socket int) bool {
	t.Helper()
	_, err := fmt.Fprintln(p.input, socket)
	require(t, err)
	var allowed bool
	require(t, p.output.Decode(&allowed))
	return allowed
}

// 仅在本轮 Docker 网关的两个数据面接口接收报头和数据长度，按实验五元组计数。
func gatewayPacketObserver(t *testing.T, name string) int {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	require(t, err)
	var protocol [2]byte
	binary.BigEndian.PutUint16(protocol[:], unix.ETH_P_ALL)
	native := binary.NativeEndian.Uint16(protocol[:])
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(native))
	require(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	require(t, unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: native, Ifindex: iface.Index}))
	return fd
}

func observedGatewayPayloads(t *testing.T, fd int, f gatewayblock.Flow) int {
	t.Helper()
	var buffer [65536]byte
	packets := 0
	for {
		n, _, err := unix.Recvfrom(fd, buffer[:], 0)
		if errors.Is(err, unix.EAGAIN) {
			return packets
		}
		require(t, err)
		if n < 40 || buffer[0]>>4 != 4 || buffer[9] != 6 {
			continue
		}
		ipLength := int(buffer[0]&0x0f) * 4
		if ipLength < 20 || ipLength+20 > n {
			continue
		}
		tcp := buffer[ipLength:n]
		src, dst := netip.AddrFrom4([4]byte(buffer[12:16])), netip.AddrFrom4([4]byte(buffer[16:20]))
		if src == f.SourceIP && dst == f.DestinationIP && binary.BigEndian.Uint16(tcp[0:2]) == f.SourcePort &&
			binary.BigEndian.Uint16(tcp[2:4]) == f.DestinationPort && len(tcp) > int(tcp[12]>>4)*4 {
			packets++
		}
	}
}

func startLiveGatewayAgent(t *testing.T, ctx context.Context, f *gatewayFixture, local gatewayblock.LocalConfig) {
	t.Helper()
	dir := t.TempDir()
	link := startGatewayControl(t, f, dir)
	id := f.id
	f.startAgent(dir, link, local)
	eventually(t, ctx, "网关经双向认证登记实际防火墙", func() bool {
		sensors, err := f.db.Runtime.Sensors(ctx, id.TenantID)
		require(t, err)
		for _, sensor := range sensors {
			var h model.HostHealth
			if sensor.ID == id.SensorID && json.Unmarshal(sensor.Health, &h) == nil &&
				h.GatewayBlock != nil && *h.GatewayBlock == local.Binding() {
				return true
			}
		}
		return false
	})
}

func awaitGatewayNft(t *testing.T, f *gatewayFixture, event string) gatewayblock.Result {
	t.Helper()
	var result gatewayblock.Result
	eventually(t, f.ctx, "实际 nftables 回执入库", func() bool {
		record := f.gatewayRecord(event)
		if record.State == "denied" {
			t.Fatal("实验连接未被授权", record.Code)
		}
		if record.TaskID == "" {
			return false
		}
		task, err := f.db.Runtime.Task(f.ctx, f.id.TenantID, record.TaskID)
		require(t, err)
		if task.State == "failed" || task.State == "unknown" {
			t.Fatal("实际网关执行未确认", string(task.Receipt))
		}
		if task.State != "succeeded" {
			return false
		}
		var receipt struct{ Result gatewayblock.Result }
		require(t, json.Unmarshal(task.Receipt, &receipt))
		result = receipt.Result
		return true
	})
	return result
}

func TestGatewayBlockLiveDockerForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	t.Cleanup(cancel)
	src, dst := netip.MustParseAddr("10.203.35.3"), netip.MustParseAddr("10.203.36.3")
	pid, err := strconv.Atoi(os.Getenv("SB_GATEWAY_CLIENT_PID"))
	require(t, err)
	if pid < 2 || os.Getenv("SB_GATEWAY_FIXTURE") == "" {
		t.Fatal("没有已核对的专属 Docker 拓扑")
	}
	left := gatewayPacketObserver(t, os.Getenv("SB_GATEWAY_LEFT_IFACE"))
	right := gatewayPacketObserver(t, os.Getenv("SB_GATEWAY_RIGHT_IFACE"))
	peer := startGatewayHTTPPeer(t, ctx, pid, os.Getenv("SB_GATEWAY_FIXTURE"), dst.String())
	scope := gatewayblock.Scope{Sources: []netip.Prefix{netip.PrefixFrom(src, 32)}, Destinations: []netip.Prefix{netip.PrefixFrom(dst, 32)}}
	f := newGatewayFixture(t, ctx, scope)
	startLiveGatewayAgent(t, ctx, f, gatewayblock.LocalConfig{Enabled: true, Scope: scope})
	f.policies(8)
	f.settings(true, 2)
	indexer := f.indexer()

	for _, trigger := range []string{gatewayblock.Rule, gatewayblock.Review} {
		flow := gatewayblock.Flow{SourceIP: src, SourcePort: peer.ports[0], DestinationIP: dst, DestinationPort: 8080, Transport: "tcp"}
		observedGatewayPayloads(t, left, flow)
		observedGatewayPayloads(t, right, flow)
		if !peer.exchange(t, 0) || observedGatewayPayloads(t, left, flow) < 1 || observedGatewayPayloads(t, right, flow) < 1 {
			t.Fatal("触发前的合法 HTTP 流量未在网关两侧观察到")
		}
		a := f.observe("1003340", src.String(), dst.String(), flow.SourcePort)
		if trigger == gatewayblock.Review {
			a.Rule.ID = "1003341"
		}
		a, envelope := f.envelope(a)
		require(t, indexer.Process(ctx, envelope))
		if trigger == gatewayblock.Review {
			f.refreshAlerts()
			input := f.assessment(a, 0, "confirmed")
			f.client.request("POST", "/alerts/"+a.EventID+"/gateway-blocks", "approve_live_gateway", input, nil, 202)
		}
		record := f.gatewayRecord(a.EventID)
		result := awaitGatewayNft(t, f, a.EventID)
		observedGatewayPayloads(t, left, flow)
		observedGatewayPayloads(t, right, flow)
		if result.Flow != flow || peer.exchange(t, 0) || !peer.exchange(t, 1) {
			t.Fatal("命中的连接未中止数据交付，或相邻连接受到影响", trigger)
		}
		in, out := observedGatewayPayloads(t, left, flow), observedGatewayPayloads(t, right, flow)
		if in < 1 || out != 0 {
			t.Fatal("限时阻断的两侧抓包结果不符", trigger, in, out)
		}
		t.Logf("%s 触发到独立回读 %s。观测到回读 %s。目标请求入侧 %d 包、出侧 %d 包。对照连接正常。",
			trigger, result.VerifiedAt.Sub(record.CreatedAt).Round(time.Millisecond),
			result.VerifiedAt.Sub(a.ObservedAt).Round(time.Millisecond), in, out)
		eventually(t, ctx, "本地租约到期，原始连接恢复数据传输", func() bool {
			return time.Now().After(result.LeaseUntil) && peer.exchange(t, 0)
		})
	}

	a := f.observe("1003340", src.String(), dst.String(), peer.ports[0])
	f.indexAlerts(a)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{a}))
	eventually(t, ctx, "真实网关仍可访问，分钟上限拒绝第三条请求", func() bool {
		return f.gatewayRecord(a.EventID).Code == "rate_limited"
	})
	list := watchlistInput("live_gateway_protection")
	list.Definition.Sensors = []watchlist.Sensor{{SensorID: f.id.SensorID, RegistrationID: f.id.RegistrationID}}
	list.Definition.Values = []string{dst.String()}
	f.client.request("POST", "/watchlists", list.ID, list, nil, 200)
	b := f.observe("1003340", src.String(), dst.String(), peer.ports[0])
	f.indexAlerts(b)
	require(t, f.db.Runtime.RecordGatewayBlockMatches(ctx, f.id.TenantID, []model.Alert{b}))
	eventually(t, ctx, "真实网关仍可访问，目标保护名单生效", func() bool {
		return f.gatewayRecord(b.EventID).Code == "protected_endpoint"
	})
	if !peer.exchange(t, 0) || !peer.exchange(t, 1) {
		t.Fatal("拒绝请求影响了实验连接")
	}
	t.Log("分钟上限和保护名单的拒绝均已落盘，原始与对照连接正常。")
}
