package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMaintenanceCommandDispatchAndLoopbackProbe(t *testing.T) {
	for _, args := range [][]string{nil, {"--version"}, {"unrelated"}} {
		if handled, err := maintenance(args); handled || err != nil {
			t.Fatal("常规采集器参数被维护入口截获", args, err)
		}
	}
	for _, args := range [][]string{{"maintenance"}, {"maintenance-probe", "--unknown"}, {"maintenance-probe", "extra"}, {"maintenance-boot", "--root", "/does/not/exist"}, {"maintenance-run", "--root", "/does/not/exist", "--binary", "/bin/sh"}} {
		if handled, err := maintenance(args); !handled || err == nil {
			t.Fatal("无效维护请求被接受", args, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Error("就绪探测使用了错误路径")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	if handled, err := maintenance([]string{"maintenance-probe", "--url", server.URL + "/readyz"}); !handled || err != nil {
		t.Fatal(err)
	}
}
