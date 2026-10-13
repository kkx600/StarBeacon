import {webcrypto,randomUUID} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import {Form,Select} from 'ant-design-vue'
import {registerAnt} from '@starbeacon/shared/ant.ts'
import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
import {principal,click,deferred} from './fixtures'
import {responseEvaluation,responseSensor} from './decisionResponseFixtures'
import {orderedPolicy,orderedContinuous,validPolicyDefinition,validContinuous,validTriageTrigger,validPolicy,type PolicyDefinition} from '../platform/src/features/decisions/decisionPolicies'
import {orderedEvaluation,type EvaluationRecord} from '../platform/src/features/decisions/decisionEvaluations'
import {orderedContinuousRecord,validContinuousRecord,type ContinuousRecord} from '../platform/src/features/decisions/continuousDecisions'
import DecisionPolicyForm from '../platform/src/features/decisions/DecisionPolicyForm.vue'
import ContinuousDecisionPanel from '../platform/src/features/decisions/ContinuousDecisionPanel.vue'
import AutomaticTriagePanel from '../platform/src/features/decisions/AutomaticTriagePanel.vue'
import {validAutomaticTriagePage,type AutomaticTriageRecord} from '../platform/src/features/decisions/automaticTriage'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const body=()=>new DOMWrapper(document.body)
async function evaluation(mode:'approval'|'automatic'='automatic'):Promise<EvaluationRecord>{
 const e=await responseEvaluation(),s=responseSensor()
 e.policy.definition={...e.policy.definition,mode,continuous:{provider_id:e.result.provider_id,provider_revision:e.result.provider_revision,...(mode==='automatic'?{automatic:{sensor_id:s.id,registration_id:s.registration_id,connector_id:'connector_test',config_sha256:'a'.repeat(64),ttl_seconds:300,cooldown_seconds:3600,max_hourly_actions:10,accept_uncalibrated_score:true}}:{})}}
 e.policy.definition_sha256=await goJSONDigest(orderedPolicy(e.policy.definition));e.result.definition_sha256=e.policy.definition_sha256;e.sha256=await goJSONDigest(orderedEvaluation(e));return e
}
async function run(e:EvaluationRecord,state:ContinuousRecord['state']='queued',code:ContinuousRecord['code']='policy_authorized'):Promise<ContinuousRecord>{
 const r:ContinuousRecord={schema_version:'decision-continuous.v1',tenant_id:e.tenant_id,id:'continuous_owned',created_by:e.created_by,evaluation_id:e.id,evaluation_sha256:e.sha256,policy_id:e.policy.id,policy_revision:e.policy.revision,definition_sha256:e.policy.definition_sha256,triage_id:e.result.triage_id,event_id:e.result.event_id,raw_sha256:e.result.raw_sha256,target_ip:e.result.target_ip,config:e.policy.definition.continuous!,state,code,task_id:state==='queued'?'task_owned':'',created_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString(),sha256:''};r.sha256=await goJSONDigest(orderedContinuousRecord(r));return r
}
beforeEach(()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID})})
describe('持续决策配置与独立授权契约',()=>{
 it('触发记录核对原策略、探针、修订、状态和分页，拒绝不完整或混入其他范围的回执',async()=>{
  const e=await evaluation(),a=e.policy.definition.continuous!.automatic!
  const r:AutomaticTriageRecord={id:'trigger_01',policy_id:e.policy.id,policy_revision:e.policy.revision,definition_sha256:e.policy.definition_sha256,event_id:e.result.event_id,raw_sha256:e.result.raw_sha256,sensor_id:a.sensor_id,registration_id:a.registration_id,state:'submitted',code:'model_queue_accepted',triage_id:e.result.triage_id,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString()}
  expect(validAutomaticTriagePage({items:[r],next_cursor:''},e.policy,'')).toBe(true)
  for(const item of [null,{}, {...r,extra:true},{...r,id:'/'},{...r,policy_id:'other'},{...r,policy_revision:0},{...r,definition_sha256:'f'.repeat(64)},{...r,event_id:'/'},{...r,raw_sha256:'bad'},{...r,sensor_id:'other'},{...r,registration_id:'other'},{...r,state:'completed'},{...r,code:'model_invoked'},{...r,triage_id:''},{...r,created_at:'bad'},{...r,expires_at:r.created_at},{...r,state:'pending'},{...r,state:'skipped',triage_id:''}])expect(validAutomaticTriagePage({items:[item],next_cursor:''},e.policy,'')).toBe(false)
  expect(validAutomaticTriagePage({items:[{...r,state:'pending',code:'awaiting_model_queue',triage_id:''}],next_cursor:''},e.policy,'')).toBe(true)
  expect(validAutomaticTriagePage({items:[{...r,state:'skipped',code:'model_quota',triage_id:''}],next_cursor:''},e.policy,'')).toBe(true)
  for(const p of [null,[],{items:[r]},{items:[r,r],next_cursor:''},{items:[r],next_cursor:r.id},{items:[],next_cursor:'/'},{items:[],next_cursor:'',extra:true}])expect(validAutomaticTriagePage(p,e.policy,'')).toBe(false)
  expect(validAutomaticTriagePage({items:[r],next_cursor:''},e.policy,r.id)).toBe(false)
 })
 it('自动研判许可独立于执行许可，限定等级和费用额度并绑定策略摘要',async()=>{
  const e=await evaluation(),t={severities:['critical','high'],max_daily_jobs:100,allow_model_context:true as const},c={...e.policy.definition.continuous!,trigger:t}
  expect(validTriageTrigger(t)).toBe(true);expect(validContinuous(c,'automatic')).toBe(true)
  expect(orderedContinuous(c).trigger).toEqual(t);expect(validContinuous(c,'approval')).toBe(false)
  for(const value of [null,{}, {...t,extra:true},{...t,allow_model_context:false},{...t,severities:[]},{...t,severities:['high','high']},{...t,severities:['unknown']},{...t,max_daily_jobs:0},{...t,max_daily_jobs:1001},{...t,max_daily_jobs:1.5}]){expect(validTriageTrigger(value)).toBe(false);expect(validContinuous({...c,trigger:value},'automatic')).toBe(false)}
  const prior=e.policy.definition_sha256;e.policy.definition.continuous=c
  expect(await validPolicy(e.policy,e.tenant_id)).toBe(false)
  e.policy.definition_sha256=await goJSONDigest(orderedPolicy(e.policy.definition));expect(e.policy.definition_sha256).not.toBe(prior);expect(await validPolicy(e.policy,e.tenant_id)).toBe(true)
 })
 it('保留旧影子摘要，自动模式必须绑定模型、设备与明确评分授权',async()=>{
  const e=await evaluation(),d=e.policy.definition,c=d.continuous!,a=c.automatic!
  expect(validPolicyDefinition(d)).toBe(true);expect(await validPolicy(e.policy,e.tenant_id)).toBe(true)
  const approval=(await evaluation('approval')).policy.definition
  expect(validPolicyDefinition(approval)).toBe(true);expect(orderedContinuous(approval.continuous!)).toEqual(approval.continuous)
  const shadow=(await responseEvaluation()).policy.definition;expect(Object.keys(orderedPolicy(shadow))).toHaveLength(7)
  for(const bad of [null,{}, {...c,provider_id:'/'},{...c,provider_revision:0},{...c,automatic:undefined},{...c,automatic:{...a,accept_uncalibrated_score:false}},{...c,automatic:{...a,sensor_id:'/'}},{...c,automatic:{...a,registration_id:'/'}},{...c,automatic:{...a,connector_id:'/'}},{...c,automatic:{...a,config_sha256:'bad'}},{...c,automatic:{...a,ttl_seconds:29}},{...c,automatic:{...a,ttl_seconds:3601}},{...c,automatic:{...a,cooldown_seconds:299}},{...c,automatic:{...a,cooldown_seconds:86401}},{...c,automatic:{...a,max_hourly_actions:0}},{...c,automatic:{...a,max_hourly_actions:101}}])expect(validContinuous(bad,'automatic')).toBe(false)
  expect(validContinuous(c,'approval')).toBe(false)
  for(const bad of [{...d,threshold:.49},{...d,candidate_action:'notify'},{...d,continuous:null},{...d,mode:'shadow'},{...approval,continuous:c}])expect(validPolicyDefinition(bad)).toBe(false)
 })
 it('完整核对授权快照和状态，不把任务受理当作设备效果',async()=>{
  const e=await evaluation(),r=await run(e)
  expect(await validContinuousRecord(r,e,e.tenant_id,e.created_by)).toBe(true)
  for(const bad of [null,[],{}, {...r,extra:true},{...r,tenant_id:'other'},{...r,created_by:'other'},{...r,evaluation_id:'evaluation_other'},{...r,evaluation_sha256:'f'.repeat(64)},{...r,policy_revision:2},{...r,definition_sha256:'f'.repeat(64)},{...r,triage_id:'triage_other'},{...r,event_id:'event_other'},{...r,raw_sha256:'f'.repeat(64)},{...r,target_ip:'198.51.100.22'},{...r,state:'blocked'},{...r,code:'device_blocked'},{...r,task_id:''},{...r,created_at:'bad'},{...r,expires_at:r.created_at},{...r,sha256:'f'.repeat(64)}])expect(await validContinuousRecord(bad,e,e.tenant_id,e.created_by)).toBe(false)
  expect(await validContinuousRecord(await run(e,'skipped','target_cooldown'),e,e.tenant_id,e.created_by)).toBe(true)
  expect(await validContinuousRecord(await run(e,'skipped','policy_authorized'),e,e.tenant_id,e.created_by)).toBe(false)
  const approval=await evaluation('approval');expect(await validContinuousRecord(await run(approval,'awaiting_confirmation','manual_confirmation_required'),approval,e.tenant_id,e.created_by)).toBe(true)
  expect(await validContinuousRecord(await run(e,'awaiting_confirmation','manual_confirmation_required'),e,e.tenant_id,e.created_by)).toBe(false)
  expect(await validContinuousRecord(await run(approval),approval,e.tenant_id,e.created_by)).toBe(false)
 })
})
describe('持续决策表单与授权详情交互',()=>{
 it('触发记录使用单表弹窗视图，分页、错误、决策跳转与身份撤回均保留真实边界',async()=>{
  const e=await evaluation(),a=e.policy.definition.continuous!.automatic!,router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:defineComponent({render:()=>h('div')})}]});await router.push('/models');await router.isReady()
  const row=(i:number):AutomaticTriageRecord=>({id:'trigger_'+String(i).padStart(2,'0'),policy_id:e.policy.id,policy_revision:e.policy.revision,definition_sha256:e.policy.definition_sha256,event_id:e.result.event_id,raw_sha256:e.result.raw_sha256,sensor_id:a.sensor_id,registration_id:a.registration_id,state:'submitted',code:'model_queue_accepted',triage_id:e.result.triage_id,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString()})
  const first={items:Array.from({length:20},(_,i)=>row(i+1)),next_cursor:'trigger_20'}
  request.mockResolvedValueOnce(first)
  const w=mount(AutomaticTriagePanel,{props:{record:e.policy},attachTo:document.body,global:{plugins:[registerAnt,router]}});await flushPromises();expect(w.findAll('table')).toHaveLength(1);expect(w.text()).toContain('模型队列已受理')
  request.mockResolvedValueOnce({items:[row(21)],next_cursor:''});await click('下一页');expect(request.mock.lastCall?.[0]).toContain('?before=trigger_20');expect(w.text()).toContain('当前页 1 条')
  await click('查看决策记录');expect(router.currentRoute.value.query.triage_id).toBe(e.result.triage_id)
  request.mockResolvedValueOnce(first);await click('上一页');expect(w.text()).toContain('当前页 20 条')
  request.mockRejectedValueOnce(new Error('执行记录服务暂不可用'));await click('刷新记录');expect(w.text()).toContain('执行记录服务暂不可用');expect(w.text()).not.toContain('暂无自动研判登记')
  request.mockResolvedValueOnce({items:[{...row(1),sensor_id:'other'}],next_cursor:''});await click('重试');expect(w.text()).toContain('修订不一致')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('刷新记录');const signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,id:'other'};await flushPromises();late.resolve(first);await flushPromises();expect(signal.aborted).toBe(true);expect(w.text()).toContain('没有该策略自动研判记录的查看权限');expect(w.text()).not.toContain('模型队列已受理');w.unmount()
 })
 it('自动提交默认关闭，开启后须单独确认数据使用与费用，模型变化撤回两项许可',async()=>{
  const e=await evaluation(),s=responseSensor()
  request.mockImplementation(async(path:string)=>path==='/models/providers'?{items:[{id:e.result.provider_id,revision:e.result.provider_revision,name:'研判模型',enabled:true}]}:{items:[s],next_cursor:''})
  const w=mount(DecisionPolicyForm,{props:{record:null,draft:{id:e.policy.id,expected_revision:0,name:e.policy.name,description:e.policy.description,active:true,definition:e.policy.definition},busy:false,unconfirmed:false,error:''},attachTo:document.body,global:{plugins:[registerAnt]}})
  await flushPromises();expect((body().find('input[aria-label="自动提交新告警研判"]').element as HTMLInputElement).checked).toBe(false)
  await body().find('input[aria-label="自动提交新告警研判"]').setValue(true);await flushPromises()
  expect(body().text()).toContain('模型可能计费');expect((body().find('input[aria-label="自动研判数据使用许可"]').element as HTMLInputElement).checked).toBe(false)
  await w.findComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('save')).toBeUndefined()
  await body().find('input[aria-label="自动研判数据使用许可"]').setValue(true)
  await w.findComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('save')?.[0]?.[0]).toMatchObject({definition:{continuous:{trigger:{severities:['critical','high'],max_daily_jobs:100,allow_model_context:true}}}})
  w.findAllComponents(Select)[3]!.vm.$emit('update:value',e.result.provider_id);await flushPromises()
  expect((body().find('input[aria-label="自动研判数据使用许可"]').element as HTMLInputElement).checked).toBe(false)
  w.unmount()
 })
 it('选择模型、探针、设备后仍须明确授权，并冻结当前注册与配置摘要',async()=>{
  const s=responseSensor()
  request.mockImplementation(async(path:string)=>path==='/models/providers'?{items:[{id:'provider_owned',revision:3,name:'本地研判模型',enabled:true}]}:{items:[s],next_cursor:''})
  const w=mount(DecisionPolicyForm,{props:{record:null,busy:false,unconfirmed:false,error:''},attachTo:document.body,global:{plugins:[registerAnt]}})
  await body().find('#policy-name').setValue('受控自动响应')
  w.findAllComponents(Select)[1]!.vm.$emit('update:value','automatic');await flushPromises()
  w.findAllComponents(Select)[3]!.vm.$emit('update:value','provider_owned');await flushPromises()
  w.findAllComponents(Select)[4]!.vm.$emit('update:value',s.id);await flushPromises()
  w.findAllComponents(Select)[5]!.vm.$emit('update:value','connector_test');await flushPromises()
  await w.findComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('save')).toBeUndefined()
  await body().find('input[type="checkbox"]').setValue(true)
  await w.findComponent(Form).vm.$emit('finish');await flushPromises()
  expect(w.emitted('save')?.[0]?.[0]).toMatchObject({definition:{mode:'automatic',candidate_action:'block_source',continuous:{provider_id:'provider_owned',provider_revision:3,automatic:{sensor_id:s.id,registration_id:s.registration_id,connector_id:'connector_test',config_sha256:'a'.repeat(64),ttl_seconds:300,cooldown_seconds:3600,accept_uncalibrated_score:true}}}})
  w.findAllComponents(Select)[3]!.vm.$emit('update:value','provider_owned');await flushPromises();expect((body().find('input[type="checkbox"]').element as HTMLInputElement).checked).toBe(false)
  await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('模型目录损坏或读取中断时显示错误，关闭后忽略迟到数据',async()=>{
  const e=await evaluation('approval');request.mockResolvedValue({items:[{id:'/',enabled:true}]})
  const w=mount(DecisionPolicyForm,{props:{record:e.policy,busy:false,unconfirmed:false,error:''},attachTo:document.body,global:{plugins:[registerAnt]}})
  await flushPromises();expect(body().text()).toContain('模型目录不完整')
  request.mockRejectedValueOnce(new Error('目录暂不可用'));await click('刷新模型与探针');expect(body().text()).toContain('目录暂不可用')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('刷新模型与探针');const signal=request.mock.lastCall?.[1].signal as AbortSignal;w.unmount();expect(signal.aborted).toBe(true);late.resolve({items:[]});await flushPromises();expect(body().text()).not.toContain('持续决策指定模型')
 })
 it('授权为空、错误、独立任务跳转及身份切换均核对原评估',async()=>{
  const e=await evaluation(),r=await run(e),router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:defineComponent({render:()=>h('div')})}]});await router.push('/models');await router.isReady()
  request.mockResolvedValue({item:null});const w=mount(ContinuousDecisionPanel,{props:{record:e},attachTo:document.body,global:{plugins:[registerAnt,router]}});await flushPromises();expect(w.text()).toContain('没有持续决策授权记录')
  request.mockResolvedValueOnce({item:{...r,task_id:'task_tampered'}});await click('刷新授权记录');await vi.waitFor(()=>expect(w.text()).toContain('摘要不一致'))
  request.mockResolvedValueOnce({item:r});await click('重试');await vi.waitFor(()=>expect(w.text()).toContain('策略已授权签名任务'));await click('查看任务记录');expect(router.currentRoute.value.query.task).toBe(r.task_id)
  request.mockResolvedValueOnce({item:await run(e,'skipped','event_already_authorized')});await click('刷新授权记录');await vi.waitFor(()=>expect(w.text()).toContain('本设备已授权同一告警'))
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('刷新授权记录');const signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,id:'other_admin'};request.mockResolvedValueOnce({item:null});await flushPromises();late.resolve({item:r});await flushPromises();expect(signal.aborted).toBe(true);expect(w.text()).not.toContain('策略已授权签名任务')
 })
})
