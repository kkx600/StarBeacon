export type ProtocolStatus = 'unknown' | 'partial' | 'disabled' | 'unlisted' | 'detection_only' | 'configured' | 'native_listed' | 'not_configured' | 'requires_validation' | 'packet_headers_only' | 'not_implemented'
export interface ProtocolBinding {transport: 'tcp' | 'udp' | 'unknown'; mode: 'yes' | 'no' | 'detection-only' | 'unknown'}
export interface ProtocolEntry {
  protocol: string
  name: string
  bindings: ProtocolBinding[]
  native_listed: boolean
  recognition: ProtocolStatus
  transactions: ProtocolStatus
  online_rules: ProtocolStatus
  file_extraction: ProtocolStatus
  packet_forensics: ProtocolStatus
  external_logs: ProtocolStatus
  qualification: 'not_qualified'
}
export interface ProtocolReport {
  schema_version: 1
  state: 'observed' | 'pending' | 'unavailable'
  observed_at: string
  source: 'managed_configuration' | 'offline_template' | 'unavailable'
  capture_active: boolean
  engine_version?: string
  engine_sha256?: string
  config_sha256?: string
  error_code?: string
  protocols: ProtocolEntry[]
  limits: {key: string; value: string}[]
}
export const protocolStatus: Record<ProtocolStatus, string> = {
  unknown: '尚未核实', partial: '传输配置有差异', disabled: '已禁用', unlisted: '原生目录未列出',
  detection_only: '仅识别', configured: '已配置', native_listed: '原生目录已列出', not_configured: '未配置日志',
  requires_validation: '需规则样本验证', packet_headers_only: '有界包头解析', not_implemented: '尚未提供',
}
export const protocolErrors: Record<string, string> = {
  inspection_pending: '协议能力正在核对，请稍后刷新。', engine_not_configured: '采集器未配置可核验的检测引擎。',
  engine_isolation_unavailable: '原生检查的隔离环境不可用，无法确认协议能力。', engine_version_mismatch: '检测引擎文件未通过固定版本核验。',
  native_protocol_inventory_unavailable: '未取得完整的原生协议目录，请检查检测引擎及隔离权限。',
  protocol_configuration_unavailable: '无法读取检测配置，不能推断协议启用状态。',
  protocol_configuration_unsupported: '配置包含未核验引用、插件或无效内容，无法确认有效配置。',
  protocol_observation_changed: '检测文件或运行状态在核对期间变化，请刷新后重试。', protocol_inspection_cancelled: '协议能力核对未完成，请稍后刷新。',
}
export const protocolLimitNames: Record<string, string> = {
  'flow.memcap': '流跟踪内存上限', 'stream.memcap': 'TCP 流内存上限', 'stream.reassembly.memcap': 'TCP 重组内存上限',
  'stream.reassembly.depth': 'TCP 重组深度', 'defrag.memcap': 'IP 分片重组内存上限',
  'app-layer.protocols.http.libhtp.default-config.request-body-limit': 'HTTP 默认请求正文深度',
  'app-layer.protocols.http.libhtp.default-config.response-body-limit': 'HTTP 默认响应正文深度',
}
const digest = /^[a-f0-9]{64}$/
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v)
export function isProtocolReport(value: unknown): value is ProtocolReport {
  if (!object(value) || value.schema_version !== 1 || typeof value.observed_at !== 'string' || !Number.isFinite(Date.parse(value.observed_at)) || typeof value.capture_active !== 'boolean' || !Array.isArray(value.protocols) || value.protocols.length > 160 || !Array.isArray(value.limits) || value.limits.length > 7) return false
  if (value.state === 'pending' || value.state === 'unavailable') return value.source === 'unavailable' && !value.capture_active && value.protocols.length === 0 && value.limits.length === 0 && !value.engine_version && !value.engine_sha256 && !value.config_sha256 && typeof value.error_code === 'string' && Object.hasOwn(protocolErrors, value.error_code)
  if (value.state !== 'observed' || value.engine_version !== '8.0.7' || typeof value.engine_sha256 !== 'string' || !digest.test(value.engine_sha256) || typeof value.config_sha256 !== 'string' || !digest.test(value.config_sha256) || value.error_code || !['managed_configuration', 'offline_template'].includes(String(value.source)) || value.capture_active && value.source !== 'managed_configuration' || !value.protocols.length || value.limits.length !== 7) return false
  const seen = new Set<string>()
  for (const row of value.protocols) {
    if (!object(row) || typeof row.protocol !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/.test(row.protocol) || seen.has(row.protocol) || typeof row.name !== 'string' || !row.name || new TextEncoder().encode(row.name).length > 64 || /\p{Cc}/u.test(row.name) || typeof row.native_listed !== 'boolean' || row.file_extraction !== 'not_implemented' || row.external_logs !== 'not_implemented' || row.qualification !== 'not_qualified' || !Array.isArray(row.bindings) || row.bindings.length > 2) return false
    seen.add(row.protocol)
    if (!['unknown', 'partial', 'disabled', 'unlisted', 'detection_only', 'configured', 'native_listed'].includes(String(row.recognition)) || !['unknown', 'partial', 'disabled', 'configured', 'not_configured'].includes(String(row.transactions)) || !['requires_validation', 'disabled'].includes(String(row.online_rules)) || !['packet_headers_only', 'not_implemented'].includes(String(row.packet_forensics))) return false
    const transports = new Set<string>()
    for (const binding of row.bindings) {
      if (!object(binding) || typeof binding.transport !== 'string' || !['tcp', 'udp', 'unknown'].includes(binding.transport) || transports.has(binding.transport) || !['yes', 'no', 'detection-only', 'unknown'].includes(String(binding.mode))) return false
      transports.add(binding.transport)
    }
  }
  const keys = new Set<string>()
  for (const limit of value.limits) {
    if (!object(limit) || typeof limit.key !== 'string' || !Object.hasOwn(protocolLimitNames, limit.key) || keys.has(limit.key) || typeof limit.value !== 'string' || limit.value !== '' && !/^[0-9]{1,16}(?:\.[0-9]{1,3})?\s*(?:[kmgt]i?b|b)?$/i.test(limit.value)) return false
    keys.add(limit.key)
  }
  return true
}
