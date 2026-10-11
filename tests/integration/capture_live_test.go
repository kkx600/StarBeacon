//go:build integration && captureintegration

package integration

import (
	"os"
	"testing"
)

// 本用例仅在带 NET_RAW 的专属 Docker 网络运行，不使用宿主网络或宿主接口。
func TestManagedCaptureNativeLiveHTTPEndToEnd(t *testing.T) {
	if os.Getenv("SB_TEST_CAPTURE_ENDPOINT") == "" {
		t.Fatal("实际网卡捕获测试要求专属 Docker 流量端点")
	}
	testLiveRolesCaptureToSearchNotificationAndReplay(t, true)
}
