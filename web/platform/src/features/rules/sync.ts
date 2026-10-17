export interface RuleSyncSpec { name:string; enabled:boolean; sensor_id:string; registration_id:string; package_id:string; package_revision:number; positive_sample_id:string; negative_sample_id:string; interval_seconds:number }
export interface RuleSyncRun {id:string;plan_revision:number;spec:RuleSyncSpec;created_by:string;state:string;code:string;stage:number;tasks:[string,string,string,string];expected_sha256:string;created_at:string;finished_at?:string;expires_at:string}
export interface RuleSyncPlan {id:string;revision:number;spec:RuleSyncSpec;created_by:string;updated_at:string;next_at:string;processed_revision:number;run?:RuleSyncRun}
export interface RuleSyncChange {id:string;expected_revision:number;spec:RuleSyncSpec}
export interface RuleSyncPage {items:RuleSyncPlan[];next_cursor:string}
export const syncStates:Record<string,string>={pending:'等待核对',validating:'装载检查',positive_replay:'正样本重放',negative_replay:'反样本重放',applying:'等待发布回执',succeeded:'规则已生效',blocked:'同步受阻',paused:'同步已暂停'}
export const syncCodes:Record<string,string>={applied:'实际规则文件与引擎回读一致',sensor_offline:'探针离线，恢复后继续核对',plan_disabled:'计划已停用，后续步骤未提交',owner_unavailable:'批准账号已停用或权限变化',sensor_identity_changed:'探针已停用或注册代次变化',device_trust_changed:'设备任务信任信息不匹配',capability_unavailable:'设备缺少所需执行能力',rules_digest_unavailable:'设备未上报有效规则摘要',rules_digest_changed:'实际规则已变化，请核对后重新授权',sample_unavailable:'样本不存在、已到期或剩余有效期不足',task_record_unavailable:'任务档案不可读取，禁止推定执行结果',task_qualification_changed:'发布资格或在途任务条件变化，请核对独立任务回执',apply_receipt_unverified:'发布回执缺少有效实际规则回读',task_failed:'任务执行失败，请查看任务详情',task_unknown:'执行结果待核实，请先处理独立任务',task_expired:'未投递任务已过期',task_cancelled:'任务已取消'}
const id=/^[a-z0-9][a-z0-9_-]{0,63}$/
export function syncInputError(c:RuleSyncChange):string {
 if(!id.test(c.id)||!Number.isSafeInteger(c.expected_revision)||c.expected_revision<0)return '计划标识或修订无效'
 const s=c.spec
 if(!s.name||s.name.trim()!==s.name||[...s.name].length>128||/[\u0000-\u001f\u007f]/.test(s.name))return '请填写 1–128 字的计划名称'
 if(!id.test(s.sensor_id)||!id.test(s.registration_id))return '请选择探针并核对注册代次'
 if(!id.test(s.package_id)||!Number.isSafeInteger(s.package_revision)||s.package_revision<1)return '请选择规则包和有效修订'
 if(!id.test(s.positive_sample_id)||!id.test(s.negative_sample_id)||s.positive_sample_id===s.negative_sample_id)return '请选择两个不同的正反样本'
 if(!Number.isInteger(s.interval_seconds)||s.interval_seconds<30||s.interval_seconds>3600)return '核对周期范围为 30–3600 秒'
 return ''
}
export function syncPlanValid(p:RuleSyncPlan):boolean {
 if(!p||!p.spec||syncInputError({id:p.id,expected_revision:p.revision,spec:p.spec})||p.revision<1||!id.test(p.created_by)||!Number.isSafeInteger(p.processed_revision)||p.processed_revision<0||![p.updated_at,p.next_at].every(s=>Number.isFinite(Date.parse(s))))return false
 const r=p.run
 return !r||!!(r.spec&&!syncInputError({id:p.id,expected_revision:r.plan_revision,spec:r.spec})&&id.test(r.created_by)&&id.test(r.id)&&Number.isSafeInteger(r.plan_revision)&&r.plan_revision>0&&r.plan_revision<=p.revision&&syncStates[r.state]&&Number.isInteger(r.stage)&&r.stage>=0&&r.stage<=4&&Array.isArray(r.tasks)&&r.tasks.length===4&&r.tasks.every(t=>t===''||id.test(t))&&typeof r.code==='string'&&typeof r.expected_sha256==='string'&&[r.created_at,r.expires_at].every(s=>Number.isFinite(Date.parse(s))))
}
