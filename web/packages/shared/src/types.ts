export interface Principal {id: string; tenant_id: string; username: string; role: 'admin' | 'viewer'; csrf_token: string}
export interface HostHealth {version: string; hostname: string; observed_at: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; rx_bytes: string; tx_bytes: string; wal_pending: number; wal_bytes: number; errors: string[]; capture_status: string; task_capabilities?:string[]; command_signer_sha256?:string; registered_rules_available?:boolean}
export interface Sensor {id: string; name: string; registration_id: string; active: boolean; created_at: string; last_seen: string | null; health: Partial<HostHealth>; status: 'online' | 'offline' | 'disabled'}
export interface Alert {event_id: string; tenant_id: string; sensor_id: string; '@timestamp': string; observed_at: string; received_at: string; source_offset: string; sequence: string; raw_sha256: string; source: {ip?: string; port?: number; mac?: string}; destination: {ip?: string; port?: number; mac?: string}; network: {transport?: string; protocol?: string}; rule: {id?: string; name?: string; revision?: string}; http: {method?: string; hostname?: string; path?: string}; suricata: {flow_id?: string; action?: string}; severity: 'high' | 'medium' | 'low' | 'unknown'; event: {kind: string; original: string}; evidence_status: string}
export interface SearchRequest {start: string; end: string; page: number; page_size: number; keyword: string; source_ip: string; destination_ip: string; protocol: string; method: string; path: string; severity: string}
export interface SearchResult {items: Alert[]; total: number; page: number; page_size: number}
export interface NetworkInterface {name: string; index: number; mac: string; mtu: number; up: boolean; loopback: boolean; addresses: string[]}
export interface CaptureConfig {interfaces: string[]; status: 'not_applied'; updated_at?: string}
export const formatTime = (value?: string | null) => value ? new Date(value).toLocaleString('zh-CN', {hour12: false}) : '未获取'
export const formatPercent = (value?: number | null) => value == null ? '未获取' : `${value.toFixed(1)}%`
export interface TaskReceipt {command_id:string;command_sha256:string;state:string;code?:string;result:Record<string,unknown>;started_at:string;finished_at?:string}
export interface SensorTask {id:string;sensor_id:string;kind:string;state:string;created_by:string;created_at:string;expires_at:string;delivery_count:number;updated_at:string;receipt:Partial<TaskReceipt>;acknowledged?:boolean;origin?:string}
export interface RulePackage {id:string;name:string;revision:number;engine_version:string;text?:string;sha256:string;created_at:string}
export const taskNames:Record<string,string> = {diagnostics:'运行诊断','rules.validate':'规则装载检查','rules.apply':'规则同步','rules.replay':'PCAP 重放'}
export const taskStates:Record<string,string> = {queued:'等待投递',delivered:'已投递',running:'执行中',succeeded:'执行成功',failed:'执行失败',unknown:'待核实',expired:'已过期',cancelled:'已取消'}
export const taskCodes:Record<string,string> = {execution_interrupted:'执行被中断，需核实实际状态',command_expired:'任务已过期或设备时钟异常',engine_not_configured:'检测引擎未配置',engine_version_mismatch:'检测引擎版本不匹配',engine_validation_failed:'规则装载检查未通过',local_storage_unavailable:'本地存储不可用',result_unknown:'执行结果无法确认',invalid_execution_result:'执行结果不符合约定',managed_rules_mismatch:'规则来源无法确认',rule_reload_failed_rolled_back:'规则重载失败，已恢复原规则'}
Object.assign(taskCodes,{replay_isolation_unavailable:'重放隔离环境不可用',replay_sample_unavailable:'样本下载或完整性核验失败',replay_sample_invalid:'PCAP 结构或数据包不符合重放边界',registered_rules_unavailable:'登记规则快照不可读取',replay_engine_failed:'原生引擎重放失败，请查看执行日志',replay_timeout:'重放超过执行期限',replay_resource_limit:'重放达到资源上限',replay_result_incomplete:'引擎结果不完整，无法确认全部包已处理'})
export interface ReplaySample {id:string;name:string;size:number;sha256:string;format:'pcap'|'pcapng';created_at:string;expires_at:string}
const healthErrors: Record<string, string> = {
  cpu_unavailable: 'CPU 指标不可用', memory_unavailable: '内存指标不可用',
  disk_unavailable: '磁盘指标不可用', network_unavailable: '网络指标不可用',
  task_rejected: '平台任务校验未通过',
  wal_unavailable: '本地队列不可用', control_unavailable: '主平台控制连接不可用',
  eve_source_unavailable: 'EVE 数据读取受阻', upload_alerts_unavailable: '告警上报受阻',
  upload_context_unavailable: '协议数据上报受阻',
}
export const formatHealthErrors = (errors?: string[]) => errors?.length
  ? errors.map(code => healthErrors[code] ?? `未识别的观测异常（${code}）`).join('；')
  : '无已报告异常'
