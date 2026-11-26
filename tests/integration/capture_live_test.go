//go:build integration && captureintegration

package integration

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/kkx600/StarBeacon/internal/gatewayblock"
)

// 本用例仅在带 NET_RAW 的专属 Docker 网络运行，不使用宿主网络或宿主接口。
func TestManagedCaptureNativeLiveHTTPEndToEnd(t *testing.T) {
	if os.Getenv("SB_TEST_CAPTURE_ENDPOINT") == "" {
		t.Fatal("实际网卡捕获测试要求专属 Docker 流量端点")
	}
	verifyGatewayOutgoingHTTP(t, gatewayblock.FlowContinued)
	verifyGatewayOutgoingHTTP(t, gatewayblock.FlowPaused)
	testLiveRolesCaptureToSearchNotificationAndReplay(t, true)
}

func verifyGatewayOutgoingHTTP(t *testing.T, wanted string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, os.Getenv("SB_TEST_CAPTURE_ENDPOINT")+"/starbeacon/gateway-observation", nil)
	require(t, err)
	socket, err := (&net.Dialer{}).DialContext(ctx, "tcp4", request.URL.Host)
	require(t, err)
	defer socket.Close()
	original := socket
	if wanted == gatewayblock.FlowPaused {
		original, err = (&net.Dialer{}).DialContext(ctx, "tcp4", request.URL.Host)
		require(t, err)
		defer original.Close()
	}
	deadline, _ := ctx.Deadline()
	require(t, socket.SetDeadline(deadline))
	source := original.LocalAddr().(*net.TCPAddr).AddrPort()
	destination := original.RemoteAddr().(*net.TCPAddr).AddrPort()
	flow := gatewayblock.Flow{SourceIP: source.Addr().Unmap(), DestinationIP: destination.Addr().Unmap(),
		SourcePort: source.Port(), DestinationPort: destination.Port(), Transport: "tcp"}
	nic := ""
	interfaces, err := net.Interfaces()
	require(t, err)
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		require(t, err)
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Unmap() == flow.SourceIP {
				nic = iface.Name
			}
		}
	}
	if nic == "" {
		t.Fatal("专属 HTTP 流量出侧网卡无法核对")
	}
	data := make(chan gatewayblock.Observation, 1)
	go func() {
		now := time.Now().UTC()
		data <- gatewayblock.ObserveEgress(ctx, nic, flow, now, now.Add(15*time.Second))
	}()
	time.Sleep(350 * time.Millisecond)
	require(t, request.Write(socket))
	reply, err := http.ReadResponse(bufio.NewReader(socket), request)
	require(t, err)
	require(t, reply.Body.Close())
	if got := <-data; reply.StatusCode != 200 || got.State != wanted || got.EgressPackets == 0 ||
		(got.OriginalPackets > 0) != (wanted == gatewayblock.FlowContinued) || got.Reconnect != nil {
		t.Fatal("真实 HTTP 出侧数据未得到准确观察", reply.StatusCode, got)
	}
}
