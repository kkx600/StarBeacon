// Package telemetry 使用低基数指标记录交付状态，指标不携带租户、IP 或载荷。
package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

var Registry = prometheus.NewRegistry()
var Accepted = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "starbeacon_ingest_accepted_records_total", Help: "持久接入确认的记录数，包含重试。"}, []string{"stream"})
var Indexed = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "starbeacon_worker_indexed_records_total", Help: "成功索引的记录处理次数，包含幂等重放。"}, []string{"stream"})
var Quarantined = prometheus.NewCounter(prometheus.CounterOpts{Name: "starbeacon_worker_quarantined_records_total", Help: "持久隔离的记录处理次数。"})
var IndexDuration = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "starbeacon_worker_batch_seconds", Help: "单批索引处理耗时。", Buckets: []float64{.01, .05, .1, .25, .5, 1, 2, 5, 10, 30, 60}})
var CommitAge = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "starbeacon_event_index_commit_age_seconds", Help: "采集器观察到事件至索引写入确认的时间差，依赖时钟同步；不包含 ES 刷新等待。", Buckets: []float64{.1, .25, .5, 1, 2, 5, 10, 30, 60, 300, 3600}})
var ClockAnomalies = prometheus.NewCounter(prometheus.CounterOpts{Name: "starbeacon_clock_anomalies_total", Help: "事件观察时间晚于平台完成时间的次数。"})
var WALPending = prometheus.NewGauge(prometheus.GaugeOpts{Name: "starbeacon_agent_wal_pending_records", Help: "采集器待传队列记录数。"})
var WALBytes = prometheus.NewGauge(prometheus.GaugeOpts{Name: "starbeacon_agent_wal_pending_bytes", Help: "采集器待传记录编码字节数，不代表数据库文件体积。"})
var ControlConnections = prometheus.NewGauge(prometheus.GaugeOpts{Name: "starbeacon_control_connections", Help: "当前已认证采集器控制连接数。"})
var CommandDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "starbeacon_command_deliveries_total", Help: "平台投递命令次数，包含重投。"}, []string{"kind"})
var CommandDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "starbeacon_agent_command_seconds", Help: "采集器命令执行耗时，不包含排队或平台确认。", Buckets: []float64{.01, .05, .1, .25, .5, 1, 2, 5, 10, 30, 60, 120}}, []string{"kind"})
var CommandResults = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "starbeacon_agent_command_results_total", Help: "采集器完成的命令次数，不包含重复投递。"}, []string{"kind", "state"})

func init() {
	Registry.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}), Accepted, Indexed, Quarantined, IndexDuration, CommitAge, ClockAnomalies, WALPending, WALBytes, ControlConnections, CommandDeliveries, CommandDuration, CommandResults)
}
func ObserveCommit(observed time.Time) {
	d := time.Since(observed).Seconds()
	if d < 0 {
		ClockAnomalies.Inc()
		return
	}
	CommitAge.Observe(d)
}
