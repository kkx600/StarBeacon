export interface Principal {id: string; tenant_id: string; username: string; role: 'admin' | 'viewer'; csrf_token: string}
export interface HostHealth {version: string; hostname: string; observed_at: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; rx_bytes: string; tx_bytes: string; wal_pending: number; wal_bytes: number; errors: string[]; capture_status: string}
export interface Sensor {id: string; name: string; registration_id: string; active: boolean; created_at: string; last_seen: string | null; health: Partial<HostHealth>; status: 'online' | 'offline' | 'disabled'}
export interface Alert {event_id: string; tenant_id: string; sensor_id: string; '@timestamp': string; observed_at: string; received_at: string; source_offset: string; sequence: string; raw_sha256: string; source: {ip?: string; port?: number; mac?: string}; destination: {ip?: string; port?: number; mac?: string}; network: {transport?: string; protocol?: string}; rule: {id?: string; name?: string; revision?: string}; http: {method?: string; hostname?: string; path?: string}; suricata: {flow_id?: string; action?: string}; severity: 'high' | 'medium' | 'low' | 'unknown'; event: {kind: string; original: string}; evidence_status: string}
export interface SearchRequest {start: string; end: string; page: number; page_size: number; keyword: string; source_ip: string; destination_ip: string; protocol: string; method: string; path: string; severity: string}
export interface SearchResult {items: Alert[]; total: number; page: number; page_size: number}
export interface NetworkInterface {name: string; index: number; mac: string; mtu: number; up: boolean; loopback: boolean; addresses: string[]}
export interface CaptureConfig {interfaces: string[]; status: 'not_applied'; updated_at?: string}
export const formatTime = (value?: string | null) => value ? new Date(value).toLocaleString('zh-CN', {hour12: false}) : '未获取'
export const formatPercent = (value?: number | null) => value == null ? '未获取' : `${value.toFixed(1)}%`
const healthErrors: Record<string, string> = {
  cpu_unavailable: 'CPU 指标不可用', memory_unavailable: '内存指标不可用',
  disk_unavailable: '磁盘指标不可用', network_unavailable: '网络指标不可用',
  wal_unavailable: '本地队列不可用', control_unavailable: '主平台控制连接不可用',
  eve_source_unavailable: 'EVE 数据读取受阻', upload_alerts_unavailable: '告警上报受阻',
  upload_context_unavailable: '协议数据上报受阻',
}
export const formatHealthErrors = (errors?: string[]) => errors?.length
  ? errors.map(code => healthErrors[code] ?? `未识别的观测异常（${code}）`).join('；')
  : '无已报告异常'
