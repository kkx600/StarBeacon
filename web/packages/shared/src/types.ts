export interface Principal {id: string; tenant_id: string; username: string; role: 'admin' | 'viewer'; csrf_token: string}
export interface HostHealth {engine_health?:import('./engineHealth').EngineHealth;protocol_capabilities?:import('./protocols').ProtocolReport;application_rules?:import('./application').ApplicationState;version: string; hostname: string; observed_at: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; rx_bytes: string; tx_bytes: string; wal_pending: number; wal_bytes: number; errors: string[]; capture_status: string; capture?:CaptureConfig; packet_archive?:import('./packetArchives').PacketHealth; network_interfaces?:NetworkInterface[];task_capabilities?:string[]; command_signer_sha256?:string; registered_rules_available?:boolean; registered_rules_sha256?:string;syslog_sources?:import('./syslog').SyslogSource[];response_connectors?:import('./response').ResponseConnector[]}
export interface Sensor {id: string; name: string; registration_id: string; active: boolean; created_at: string; last_seen: string | null; health: Partial<HostHealth>; status: 'online' | 'offline' | 'disabled';metadata_revision?:number;group_id?:string;group_name?:string;site?:string;description?:string;metadata_updated_at?:string}
export interface Alert {application?:import('./application').ApplicationAttribution;event_id: string; tenant_id: string; sensor_id: string; '@timestamp': string; observed_at: string; received_at: string; source_offset: string; sequence: string; raw_sha256: string; source: {ip?: string; port?: number; mac?: string}; destination: {ip?: string; port?: number; mac?: string}; network: {transport?: string; protocol?: string}; rule: {id?: string; name?: string; revision?: string}; http: {method?: string; hostname?: string; path?: string}; suricata: {flow_id?: string; action?: string}; severity: 'high' | 'medium' | 'low' | 'unknown'; event: {kind: string; original: string}; evidence_status: string}
export interface SearchRequest {start: string; end: string; page: number; page_size: number; keyword: string; source_ip: string; destination_ip: string; protocol: string; method: string; path: string; severity: string; filter?: string}
export interface SearchResult {items: Alert[]; total: number; page: number; page_size: number}
export interface NetworkInterface {name: string; index: number; mac: string; mtu: number; up: boolean; loopback: boolean; addresses: string[]}
export interface CaptureSettings {interfaces:string[];threads?:number;bpf_filter?:string;promiscuous?:boolean|null}
export interface CaptureConfig extends CaptureSettings {status:'not_applied'|'pending'|'starting'|'running'|'stopped'|'degraded'|'failed';managed?:boolean;revision?:number;applied_revision?:number;applied_settings?:CaptureSettings;updated_at?:string;observed_at?:string;config_sha256?:string;settings_sha256?:string;error_code?:string;pid?:number;counters?:Record<string,string>;counters_observed_at?:string;spool_bytes?:string;spool_budget?:string;rotations?:string;rotation_pending?:boolean;quality?:import('./detectionQuality').QualityReport}
export const captureStates:Record<CaptureConfig['status'],string>={not_applied:'待应用',pending:'等待应用',starting:'启动中',running:'采集中',stopped:'已停止',degraded:'运行异常',failed:'启动失败'}
export const captureErrors:Record<string,string>={capture_filter_compiler_unavailable:'BPF 编译器不可用，请核对系统依赖及隔离权限',capture_filter_resource_limit:'BPF 编译达到资源上限，请简化过滤条件后重试',capture_filter_invalid:'BPF 捕获过滤器未通过原生编译检查，目标配置未生效；请核对实际采集状态',capture_interface_unavailable:'采集网卡不可用，请核对链路状态',capture_template_invalid:'检测配置模板无效',capture_start_failed:'检测进程未启动；原进程恢复结果请以生效配置为准',capture_spool_full:'采集缓冲额度已用尽，已停止采集；请处理待传数据及存储容量',capture_process_or_configuration_changed:'检测进程或配置与启动记录不一致，需要核对',rule_operation_in_progress:'规则事务正在执行，采集配置等待应用',rule_recovery_required:'规则恢复记录尚未核实',local_storage_unavailable:'本地持久存储不可用',registered_rules_unavailable:'登记规则不可读取',engine_validation_failed:'检测配置或规则未通过原生装载检查',engine_isolation_unavailable:'原生引擎隔离环境不可用',engine_resource_limit:'检测配置检查达到资源上限',engine_version_mismatch:'检测引擎版本不匹配',engine_not_configured:'检测引擎配置不完整'}
captureErrors.capture_rotation_unavailable='EVE 轮转或持久检查点无法核对，已停止采集；请保留缓冲文件并检查存储与检测进程'
export interface PlatformHealth {services:Record<string,string>;observed_at:string;runtime:{version:string;commit:string;observed_at:string;cpu_percent:number|null;memory_percent:number|null;disk_percent:number|null;heap_bytes:string;goroutines:number;errors:string[]}}
export interface AuditRecord {id:string;user_id?:string;username:string;action:string;object_id?:string;request_id:string;source_ip:string;user_agent:string;reason?:string;success?:boolean;phase?:string;created_at:string}
export interface AuditResult {items:AuditRecord[];next_cursor:string}
export const formatTime = (value?: string | null) => value ? new Date(value).toLocaleString('zh-CN', {hour12: false}) : '未获取'
export const formatPercent = (value?: number | null) => value == null ? '未获取' : `${value.toFixed(1)}%`
export interface TaskReceipt {command_id:string;command_sha256:string;state:string;code?:string;result:Record<string,unknown>;started_at:string;finished_at?:string}
export interface RuleResolution {task_id:string;confirmed_at:string;result:{verified:boolean;active_sha256:string;unknown_task_id:string;unknown_command_sha256:string;config_sha256:string;profile_sha256:string;ruleset_stats:unknown}}
export interface SensorTask {id:string;sensor_id:string;kind:string;state:string;created_by:string;created_at:string;expires_at:string;retain_until?:string;retention_protected?:boolean;delivery_count:number;updated_at:string;receipt:Partial<TaskReceipt>;acknowledged?:boolean;origin?:string;rule_resolution?:RuleResolution;response_action?:import('./response').ResponseAction}
export interface TaskDetailState {open:boolean;item:SensorTask|null;pending:boolean;error:string}
export interface RulePackage {id:string;name:string;revision:number;engine_version:string;text?:string;sha256:string;created_at:string;generation_id?:string;generation_sid?:number}
export const taskNames:Record<string,string> = {diagnostics:'运行诊断','applications.apply':'应用规则部署','capture.configure':'采集配置','rules.validate':'规则装载检查','rules.apply':'规则发布','rules.reconcile':'规则核实','rules.replay':'PCAP 重放'}
Object.assign(taskNames,{'response.block':'限时封禁','response.read':'联动状态回读','response.revoke':'解除封禁'})
export const taskStates:Record<string,string> = {queued:'等待投递',delivered:'已投递',running:'执行中',succeeded:'执行成功',failed:'执行失败',unknown:'待核实',expired:'已过期',cancelled:'已取消'}
export const taskCodes:Record<string,string> = {execution_interrupted:'执行被中断，需核实实际状态',command_expired:'任务已过期或设备时钟异常',engine_not_configured:'检测引擎未配置',engine_version_mismatch:'检测引擎版本不匹配',engine_validation_failed:'规则装载检查未通过',local_storage_unavailable:'本地存储不可用',result_unknown:'执行结果无法确认',invalid_execution_result:'执行结果不符合约定',managed_rules_mismatch:'规则来源无法确认',rule_reload_failed_rolled_back:'规则重载失败，已恢复原规则'}
Object.assign(taskCodes,{engine_isolation_unavailable:'检测引擎隔离环境不可用',engine_resource_limit:'规则装载检查达到执行资源上限'})
Object.assign(taskCodes,{response_scope_invalid:'联动目标、范围或期限不符合授权',response_device_unavailable:'联动设备身份、能力或认证不可用'})
Object.assign(taskCodes,captureErrors,{capture_not_managed:'设备未启用托管采集',invalid_capture_configuration:'采集配置或本机网卡不可用',capture_operation_in_progress:'设备正在应用采集配置',capture_configuration_changed:'采集配置已变化，请刷新探针状态后核对',capture_application_unconfirmed:'期望配置已保存，实际采集状态尚未确认',command_cancelled:'配置执行已取消，实际状态以设备回读为准'})
Object.assign(taskCodes,{release_validation_required:'规则发布证据不足或不符合资格',release_configuration_changed:'检测配置与验证依据发生变化',active_rules_changed:'当前规则摘要发生变化，请刷新核对',reconciliation_unavailable:'原设备规则事务无法核实',rule_operation_in_progress:'设备正在安装、恢复或核实规则',rule_apply_not_authorized:'设备未授权规则部署',managed_rules_unavailable:'现有规则超出回滚边界'})
Object.assign(taskCodes,{replay_isolation_unavailable:'重放隔离环境不可用',replay_sample_unavailable:'样本下载或完整性核验失败',replay_sample_invalid:'PCAP 结构或数据包不符合重放边界',registered_rules_unavailable:'登记规则快照不可读取',replay_engine_failed:'原生引擎重放失败，请查看执行日志',replay_timeout:'重放超过执行期限',replay_resource_limit:'重放达到资源上限',replay_result_incomplete:'引擎结果不完整，无法确认全部包已处理'})
export interface SampleOrigin {kind:'http_raw';synthetic:true;raw_sha256:string;raw_bytes:number;encoder:'http-raw-tcp/1';segment_bytes:1460}
export interface ReplaySample {id:string;name:string;size:number;sha256:string;format:'pcap'|'pcapng';created_at:string;expires_at:string;origin?:SampleOrigin}
const healthErrors: Record<string, string> = {
  ...captureErrors,
  application_state_unavailable:'应用规则状态无法核对，基础采集继续上报；请保留配置并检查本地持久状态',
  cpu_unavailable: 'CPU 指标不可用', memory_unavailable: '内存指标不可用',
  disk_unavailable: '磁盘指标不可用', network_unavailable: '网络指标不可用',
  network_inventory_unavailable:'网卡清单无法完整观测，请核对设备网络环境',
  task_rejected: '平台任务校验未通过',
  task_history_cleanup_unavailable: '任务历史清理未完成，请核对本地存储；原记录继续保留',
  wal_unavailable: '本地队列不可用', control_unavailable: '主平台控制连接不可用',
  eve_source_unavailable: 'EVE 数据读取受阻', upload_alerts_unavailable: '告警上报受阻',
  upload_context_unavailable: '协议数据上报受阻',
  packet_capture_unavailable:'独立原包捕获受阻，请核对网卡、过滤器和暂存额度',
  packet_upload_unavailable:'原包归档上报受阻，本机未确认原件继续保留',
}
export const formatHealthErrors = (errors?: string[]) => errors?.length
  ? errors.map(code => healthErrors[code] ?? `未识别的观测异常（${code}）`).join('；')
  : '无已报告异常'

Object.assign(taskCodes,{invalid_application_package:'应用规则包无效或与注册身份不一致',application_state_conflict:'采集器应用规则状态已变化，请刷新后核对',application_storage_unavailable:'本地应用规则持久存储不可用',application_service_unavailable:'采集器应用识别服务未就绪',application_apply_cancelled:'应用规则安装已取消'})
