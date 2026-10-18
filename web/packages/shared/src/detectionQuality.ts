export const qualityCounters = {
  'capture.kernel_packets': ['内核捕获包数', 'capture', 'counter'],
  'capture.kernel_drops': ['内核丢包', 'capture', 'counter'],
  'capture.errors': ['捕获错误', 'capture', 'counter'],
  'decoder.pkts': ['解码包数', 'volume', 'counter'],
  'decoder.bytes': ['解码字节', 'volume', 'counter'],
  'flow.active': ['活跃流', 'volume', 'gauge'],
  'tcp.ssn_memcap_drop': ['TCP 会话内存受限', 'inspection', 'counter'],
  'tcp.segment_memcap_drop': ['TCP 分段内存受限', 'inspection', 'counter'],
  'tcp.stream_depth_reached': ['TCP 重组深度受限', 'inspection', 'counter'],
  'tcp.reassembly_gap': ['TCP 重组缺口', 'inspection', 'counter'],
  'tcp.pkt_on_wrong_thread': ['TCP 线程归属异常', 'inspection', 'counter'],
  'tcp.ack_unseen_data': ['TCP 确认了未见数据', 'inspection', 'counter'],
  'tcp.overlap_diff_data': ['TCP 重叠字节冲突', 'inspection', 'counter'],
  'tcp.invalid_checksum': ['TCP 校验和异常', 'inspection', 'counter'],
  'tcp.midstream_pickups': ['TCP 中途接管', 'inspection', 'counter'],
  'defrag.max_trackers_reached': ['分片跟踪额度受限', 'inspection', 'counter'],
  'defrag.max_frags_reached': ['分片数量受限', 'inspection', 'counter'],
  'defrag.wrk.tracker_timeout': ['分片跟踪超时', 'inspection', 'counter'],
  'flow.memcap': ['流表内存受限', 'inspection', 'counter'],
  'flow.emerg_mode_entered': ['流表应急模式', 'inspection', 'counter'],
  'detect.alert': ['引擎告警', 'volume', 'counter'],
  'detect.alert_queue_overflow': ['告警队列溢出', 'alerting', 'counter'],
  'detect.alerts_suppressed': ['规则告警抑制', 'policy', 'counter'],
  'flow_bypassed.local_pkts': ['本地旁路包数', 'policy', 'counter'],
  'flow_bypassed.local_capture_pkts': ['本地与捕获旁路包数', 'policy', 'counter'],
} as const

export type QualityCounterKey = keyof typeof qualityCounters
export interface QualityCounter {key: QualityCounterKey; layer: string; kind: 'counter'|'gauge'; total?: string; delta?: string;observed_resets?:string}
export interface QualityFacet {state: 'unknown'|'no_reported_change'|'limited'|'policy_applied'; reasons: QualityCounterKey[]}
export interface QualityReport {
  schema_version: 1; scope: 'sensor_interval'; source: 'suricata_eve_stats'; state: Exclude<keyof typeof qualityStates,'offline'>
  engine_run_id: string; config_sha256: string; evaluated_at: string; sampled_at?: string; received_at?: string; interval_started_at?: string
  reset_counters: QualityCounterKey[]; counters: QualityCounter[]; capture: QualityFacet; inspection: QualityFacet; alerting: QualityFacet; policy: QualityFacet
}
export const qualityStates = {unavailable: '尚未观测', baseline: '等待连续样本', observed: '区间观测', counter_reset: '计数发生复位', sample_gap: '采样存在间隔', stale: '观测已过期', stopped: '引擎运行未确认', offline:'探针离线'} as const
export const qualityFacetNames = {capture: '捕获质量', inspection: '检查覆盖', alerting: '告警输出', policy: '策略影响'} as const
export const qualityFacetStates = {unknown: '质量未知', no_reported_change: '未报告增量', limited: '存在覆盖限制', policy_applied: '存在策略影响'} as const
export const qualityHelp: Record<keyof typeof qualityStates, string> = {
  unavailable: '尚未取得可核对的原生统计。外部 EVE、缺测和无告警均不能据此判断检测覆盖。',
  baseline: '首个样本仅建立累计基线，取得后续连续样本后才能计算区间增量。',
  observed: '仅反映列出的原生计数在本区间的变化；没有增量不代表流量安全或检测完整。',
  counter_reset: '累计计数下降，可能发生引擎或检测线程复位。本次不计算增量，后续重新建立区间。',
  sample_gap: '采样或接收间隔超过 20 秒，或接收时间回退。本次不计算连续区间增量。',
  stale: '原生样本已超过 20 秒或时间无法核对。以下累计值仅作为历史观测保留。',
  stopped: '检测引擎没有处于可核对的运行状态。以下数据如有保留，仅代表历史观测。',
  offline: '探针当前未在线，无法确认引擎是否运行。以下数据如有保留，仅代表最后一次观测。',
}
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)
const date = (v: unknown): v is string => typeof v === 'string' && Number.isFinite(Date.parse(v))
const key = (v: unknown): v is QualityCounterKey => typeof v === 'string' && Object.hasOwn(qualityCounters, v)
const counter = (v: unknown) => v === undefined || typeof v === 'string' && /^(0|[1-9]\d{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n

// 回执需要同时绑定本次采集配置；损坏或旧端不完整的数据不能显示为正常覆盖。
export function readQuality(value: unknown, configSHA?: string): QualityReport|null {
  if (!object(value) || value.schema_version !== 1 || value.scope !== 'sensor_interval' || value.source !== 'suricata_eve_stats'
    || typeof value.state !== 'string' || !Object.hasOwn(qualityStates, value.state) || value.state==='offline' || typeof value.engine_run_id !== 'string' || typeof value.config_sha256 !== 'string'
    || !date(value.evaluated_at) || !Array.isArray(value.counters) || value.counters.length !== Object.keys(qualityCounters).length
    || !Array.isArray(value.reset_counters) || !value.reset_counters.every(key) || new Set(value.reset_counters).size !== value.reset_counters.length) return null
  if (value.sampled_at !== undefined && (!date(value.sampled_at) || !date(value.received_at)
    || !/^engine_[a-z0-9_-]{1,56}$/.test(value.engine_run_id) || !/^[a-f0-9]{64}$/.test(value.config_sha256) || value.config_sha256 !== configSHA)) return null
  if (value.state === 'observed' && (!date(value.sampled_at) || !date(value.interval_started_at) || Date.parse(value.sampled_at) <= Date.parse(value.interval_started_at)
    || Date.parse(value.sampled_at)-Date.parse(value.interval_started_at) > 20000)) return null
  const seen = new Set<string>()
  for (const row of value.counters) {
    if (!object(row) || !key(row.key) || seen.has(row.key) || row.layer !== qualityCounters[row.key][1] || row.kind !== qualityCounters[row.key][2]
      || !counter(row.total) || !counter(row.delta) || !counter(row.observed_resets) || row.kind==='gauge'&&row.observed_resets!==undefined || row.delta !== undefined && (row.total === undefined || row.kind !== 'counter' || value.state !== 'observed' || BigInt(row.delta as string) > BigInt(row.total as string))) return null
    seen.add(row.key)
  }
  for (const layer of Object.keys(qualityFacetNames)) {
    const facet = value[layer]
    if (!object(facet) || typeof facet.state !== 'string' || !Object.hasOwn(qualityFacetStates, facet.state) || !Array.isArray(facet.reasons)
      || facet.reasons.length > 25 || !facet.reasons.every(item => key(item) && qualityCounters[item][1] === layer)
      || value.state !== 'observed' && facet.state !== 'unknown') return null
  }
  return value as unknown as QualityReport
}

export function qualityDisplayState(report: QualityReport, active: boolean, online: boolean, now: number): keyof typeof qualityStates {
  if (!online) return 'offline'
  if (!active) return 'stopped'
  const sampled = Date.parse(report.sampled_at ?? report.evaluated_at), evaluated = Date.parse(report.evaluated_at)
  if (now-sampled > 20000 || now-evaluated > 20000 || sampled-now > 5000 || evaluated-now > 5000) return 'stale'
  return report.state
}
