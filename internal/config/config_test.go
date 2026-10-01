package config

import "testing"

func development(t *testing.T) {
	t.Helper()
	for _, key := range []string{"MODE", "HTTP_ADDR", "GRPC_ADDR", "DATABASE_URL", "NATS_URL", "REDIS_URL", "ES_URL", "ES_API_KEY", "TLS_CA", "TLS_CERT", "TLS_KEY", "ALLOWED_ORIGIN", "TENANT_ID", "SENSOR_ID", "REGISTRATION_ID", "LOCAL_PASSWORD", "STREAM_BYTES", "NATS_REPLICAS"} {
		t.Setenv("SB_"+key, "")
	}
	t.Setenv("SB_MODE", "development")
	t.Setenv("SB_NATS_REPLICAS", "1")
	t.Setenv("SB_DATABASE_URL", "postgres://app@127.0.0.1/db?sslmode=disable")
	t.Setenv("SB_NATS_URL", "nats://127.0.0.1:4222")
	t.Setenv("SB_REDIS_URL", "redis://127.0.0.1:6379")
	t.Setenv("SB_ES_URL", "http://127.0.0.1:9200")
	t.Setenv("SB_TLS_CA", "ca.crt")
	t.Setenv("SB_TLS_CERT", "server.crt")
	t.Setenv("SB_TLS_KEY", "server.key")
	t.Setenv("SB_ALLOWED_ORIGIN", "http://127.0.0.1:5174")
}
func TestOriginAndListenerBoundaries(t *testing.T) {
	for _, origin := range []string{"httpfake://console.example", "http://console.example/path", "http://u:p@console.example", "http://console.example?x=1"} {
		t.Run(origin, func(t *testing.T) {
			development(t)
			t.Setenv("SB_ALLOWED_ORIGIN", origin)
			if _, e := Load("platform"); e == nil {
				t.Fatal("接受了非法来源")
			}
		})
	}
	development(t)
	t.Setenv("SB_HTTP_ADDR", "0.0.0.0:8080")
	if _, e := Load("platform"); e == nil {
		t.Fatal("直接暴露了内部 HTTP 和指标")
	}
}
func TestProductionWorkerCannotFallBackToPlaintext(t *testing.T) {
	development(t)
	t.Setenv("SB_MODE", "production")
	t.Setenv("SB_TLS_CERT", "")
	t.Setenv("SB_TLS_KEY", "")
	t.Setenv("SB_NATS_REPLICAS", "3")
	if _, e := Load("worker"); e == nil {
		t.Fatal("缺少证书的生产 Worker 仍可启动")
	}
}
