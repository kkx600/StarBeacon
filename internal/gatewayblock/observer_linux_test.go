package gatewayblock

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGatewayObserverRejectsIncompleteSampling(t *testing.T) {
	flow := testFlow("10.203.35.3", "10.203.36.3", "tcp")
	now := time.Now()
	if got := ObserveEgress(t.Context(), "unused", flow, now, now.Add(ObserveWindow)); got.State != FlowUnknown || got.Code != "window_short" {
		t.Fatal("签名租约不足时不能取得完整观察", got)
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	var observation Observation
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if code := sampleEgress(cancelled, pair[0], 0, time.Now().Add(time.Second), flow, &observation); code != "observer_unavailable" {
		t.Fatal("取消观察时仍尝试确认流量结果", code)
	}
	if code := sampleEgress(t.Context(), -1, 0, time.Now().Add(time.Second), flow, &observation); code != "observer_unavailable" {
		t.Fatal("不可读的套接字仍尝试确认流量结果", code)
	}
	if code := sampleEgress(t.Context(), pair[0], 0, time.Now(), flow, &observation); code != "packet_loss" {
		t.Fatal("没有可核对的接收统计时仍接受观察", code)
	}
	// 用普通的本地进程间消息验证队列残留和非网卡数据的处理。
	if _, err := unix.Write(pair[1], []byte("窗口结束后的消息")); err != nil {
		t.Fatal(err)
	}
	if code := sampleEgress(t.Context(), pair[0], 0, time.Now(), flow, &observation); code != "packet_loss" {
		t.Fatal("采样队列未读完仍接受观察", code)
	}
	if code := sampleEgress(t.Context(), pair[0], 0, time.Now().Add(20*time.Millisecond), flow, &observation); code != "packet_loss" ||
		observation.EgressPackets != 0 || observation.OriginalPackets != 0 || observation.Reconnect != nil {
		t.Fatal("非网卡数据被当成出侧报告", code, observation)
	}
}
