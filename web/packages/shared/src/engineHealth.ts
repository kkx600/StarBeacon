export interface EngineHealth {
 schema_version:string;state:string;source:string;observed_at:string;code?:string;pid?:number;started_at?:string;config_sha256?:string;rules_sha256?:string;file_rule_count?:number;rules_loaded?:number;rules_failed:number
}
const states:Record<string,string>={observed:'最近观测通过',pending:'等待原生观测',unconfigured:'未配置原生观测',unavailable:'原生观测未通过'}
const codes:Record<string,string>={engine_observation_cancelled:'观测已取消，等待下一次核对',engine_observation_pending:'尚无有效的原生观测',engine_observation_not_configured:'未登记完整的进程、配置、规则和控制接口',rule_operation_in_progress:'规则或采集配置事务执行中，当前观察窗口等待重新核对',rule_recovery_required:'规则恢复材料尚未核实，停止后续发布',engine_process_unverified:'无法核实登记进程及其完整规则来源',registered_rules_unavailable:'登记规则文件不可读取',engine_ruleset_unavailable:'未取得原生引擎规则装载计数',engine_ruleset_mismatch:'原生装载计数与登记完整规则包不一致',engine_observation_changed:'观测期间进程、配置或规则发生变化'}
const sha=/^[a-f0-9]{64}$/
function time(value:unknown){return typeof value==='string'&&Number.isFinite(Date.parse(value))}
export function readEngineHealth(value:unknown):EngineHealth|null {
 if(!value||typeof value!=='object'||Array.isArray(value))return null
 const r=value as EngineHealth
 if(r.schema_version!=='1'||!Object.hasOwn(states,r.state)||!time(r.observed_at)||!Number.isSafeInteger(r.rules_failed)||r.rules_failed<0||r.code!==undefined&&typeof r.code!=='string')return null
 if(r.state==='observed'&&(r.code||!['managed_process','registered_process'].includes(r.source)||!Number.isSafeInteger(r.pid)||r.pid!<=0||!time(r.started_at)||Date.parse(r.started_at!)>Date.parse(r.observed_at)||!sha.test(r.config_sha256??'')||!sha.test(r.rules_sha256??'')||!Number.isSafeInteger(r.file_rule_count)||r.file_rule_count!<=0||r.rules_loaded!==r.file_rule_count||r.rules_failed!==0))return null
 return r
}
export const engineHealthStates=states
export function engineHealthReason(code:string|undefined){return code?(codes[code]??'观测原因无法识别，请核对设备版本与诊断记录'):'以最近一次观测时间核对设备状态'}
