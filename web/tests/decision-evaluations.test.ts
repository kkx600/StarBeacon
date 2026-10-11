import {webcrypto,randomUUID} from 'node:crypto'
import {defineComponent,h,shallowRef} from 'vue'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,mount,flushPromises} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import {registerAnt} from '@starbeacon/shared/ant.ts'
import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
import {ApiError} from '@starbeacon/shared/api.ts'
import {principal,click,deferred} from './fixtures'
import {triageJob} from './triageFixtures'
import {orderedPolicy,type PolicyRecord} from '../platform/src/features/decisions/decisionPolicies'
import {orderedEvaluation,validEvaluation,validEvaluationPage,type EvaluationRecord} from '../platform/src/features/decisions/decisionEvaluations'
import {useDecisionEvaluations} from '../platform/src/features/decisions/useDecisionEvaluations'
import DecisionEvaluationsWorkspace from '../platform/src/features/decisions/DecisionEvaluationsWorkspace.vue'
import DecisionPolicyEvaluation from '../platform/src/features/decisions/DecisionPolicyEvaluation.vue'
import ModelsView from '../platform/src/views/ModelsView.vue'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const filters={policy_id:'',triage_id:'',status:''}
async function source(){const j=structuredClone(triageJob),e=j.evidence;e.sha256=await goJSONDigest({event_id:e.event_id,raw_sha256:e.raw_sha256,observed_at:e.observed_at,facts:e.facts,limitations:e.limitations,limited:e.limited,sha256:''});return j}
async function record(id='evaluation_owned'):Promise<EvaluationRecord>{
 const job=await source(),definition={schema_version:'decision-policy.v1' as const,mode:'shadow' as const,expression:'confidence >= threshold',threshold:.8,candidate_action:'investigate' as const,max_age_seconds:3600,protected_prefixes:[]}
 const p:PolicyRecord={tenant_id:principal.tenant_id,id:'policy_owned',revision:1,name:'攻击尝试策略',description:'冻结历史',active:true,definition,definition_sha256:await goJSONDigest(orderedPolicy(definition)),created_by:principal.id,created_at:'2026-10-10T00:00:00Z',expires_at:'2027-04-08T00:00:00Z'}
 const e:EvaluationRecord={schema_version:'decision-evaluation.v1',tenant_id:principal.tenant_id,id,created_by:principal.id,expires_at:'2027-04-08T00:00:00Z',policy:p,result:{schema_version:'decision-shadow.v1',policy_id:p.id,policy_revision:p.revision,definition_sha256:p.definition_sha256,triage_id:job.id,provider_id:job.request.provider_id,provider_revision:job.request.provider_revision,event_id:job.request.event_id,raw_sha256:job.request.raw_sha256,evidence_sha256:job.evidence.sha256,evaluated_at:'2026-10-10T00:00:00Z',status:'matched',confidence:.87,confidence_kind:'self_reported',candidate_action:'investigate',target_ip:'',execution_authorized:false,reasons:['expression_matched'],limitations:[...job.evidence.limitations,'影子评估不创建通知、研判修改或设备动作','模型自报分数未获得场景校准资格'],cost:7},sha256:''}
 e.sha256=await goJSONDigest(orderedEvaluation(e));return e
}
function host(){let state!:ReturnType<typeof useDecisionEvaluations>;const w=mount(defineComponent({setup(){state=useDecisionEvaluations();return()=>h('div')}}));return {state,w}}
const body=()=>new DOMWrapper(document.body)
beforeEach(()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID})})
describe('持久评估档案契约',()=>{
 it('历史摘要与账号绑定，不接受授权、校准或损坏的状态',async()=>{
  const e=await record();expect(await validEvaluation(e,principal.tenant_id,principal.id)).toBe(true)
  const alterations=[null,{}, {...e,unknown:true},{...e,tenant_id:'foreign'},{...e,created_by:'other'},{...e,expires_at:e.result.evaluated_at},{...e,sha256:'0'.repeat(64)},{...e,policy:{...e.policy,definition_sha256:'0'.repeat(64)}},...[
   {execution_authorized:true},{confidence_kind:'calibrated'},{policy_revision:2},{raw_sha256:'bad'},{provider_revision:0},{target_ip:'a'.repeat(129)},{confidence:2},{cost:-1},{cost:1001},{reasons:[]},{reasons:['expression_matched','expression_matched']},{reasons:['execute']},{limitations:[]},{limitations:[...e.result.limitations.slice(0,6),'已授权执行']},{status:'protected'},{status:'abstained'},{status:'approved'},{status:'matched',cost:null},
  ].map(result=>({...e,result:{...e.result,...result}}))]
  for(const bad of alterations)expect(await validEvaluation(bad,principal.tenant_id,principal.id)).toBe(false)
  for(const kind of ['not_matched','abstained','protected'] as const){const v=structuredClone(e);v.result.status=kind;v.result.reasons=kind==='protected'?['protected_source']:kind==='abstained'?['policy_inactive']:['expression_not_matched'];if(kind!=='not_matched')v.result.cost=null;if(kind==='abstained')v.result.confidence=null;if(kind==='protected'){v.policy.definition.candidate_action='block_source';v.policy.definition.protected_prefixes=['192.0.2.0/24'];v.result.candidate_action='block_source';v.result.target_ip='192.0.2.10';v.policy.definition_sha256=await goJSONDigest(orderedPolicy(v.policy.definition));v.result.definition_sha256=v.policy.definition_sha256}v.sha256=await goJSONDigest(orderedEvaluation(v));expect(await validEvaluation(v,principal.tenant_id,principal.id)).toBe(true)}
 })
 it('拒绝重复记录、不完整游标和不符合筛选的历史',async()=>{
  const e=await record();expect(await validEvaluationPage({items:[e],next_cursor:''},principal.tenant_id,principal.id,filters)).toBe(true)
  for(const p of [null,{}, {items:[e,e],next_cursor:''},{items:[e],next_cursor:e.id},{items:[e],next_cursor:'/'},{items:[{...e,created_by:'other'}],next_cursor:''}])expect(await validEvaluationPage(p,principal.tenant_id,principal.id,filters)).toBe(false)
  for(const f of [{...filters,policy_id:'other'},{...filters,triage_id:'other'},{...filters,status:'protected'}])expect(await validEvaluationPage({items:[e],next_cursor:''},principal.tenant_id,principal.id,f)).toBe(false)
 })
})
describe('评估档案读取与交互',()=>{
 it('有界游标和账号切换撤回旧请求，筛选回到首屏',async()=>{
  const rows=await Promise.all(Array.from({length:20},(_,i)=>record('evaluation_'+i)));request.mockResolvedValueOnce({items:rows,next_cursor:rows.at(-1)!.id});const {state,w}=host();await vi.waitFor(()=>expect(state.page.value.items).toHaveLength(20));request.mockResolvedValueOnce({items:[],next_cursor:''});state.next();await flushPromises();expect(request.mock.lastCall?.[0]).toContain('cursor=evaluation_19');state.previous();await flushPromises()
  request.mockResolvedValue({items:[],next_cursor:''});state.search({...filters,policy_id:' policy_owned '});await flushPromises();expect(state.filter.value.policy_id).toBe('policy_owned');state.next();state.previous();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,id:'other'};await flushPromises();late.resolve({items:rows,next_cursor:''});await reading;expect(signal.aborted).toBe(true);expect(state.page.value.items).toEqual([]);w.unmount();await state.refresh()
 })
 it('输入错误、传输错误和不完整目录不能显示空成功',async()=>{
  request.mockResolvedValue({});const {state}=host();await flushPromises();expect(state.error.value).toContain('目录');for(const f of [{...filters,policy_id:'/'},{...filters,triage_id:'/'},{...filters,status:'approved'}]){state.search(f);expect(state.error.value).toContain('请核对')};request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toContain('读取失败')
 })
 it('单表工作区区分空状态、筛选、详情和档案已到期',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const w=mount(DecisionEvaluationsWorkspace,{attachTo:document.body,global:{plugins:[registerAnt]}});await flushPromises();expect(w.text()).toContain('暂无评估记录');await w.get('input').setValue('policy_missing');await w.get('form').trigger('submit');await flushPromises();expect(w.text()).toContain('没有符合筛选条件');await w.get('input').setValue('');await w.get('form').trigger('submit');await flushPromises()
  const e=await record();request.mockResolvedValue({items:[e],next_cursor:''});await click('刷新');await vi.waitFor(()=>expect(w.findAll('.ant-table')).toHaveLength(1));request.mockResolvedValueOnce({...e,sha256:'0'.repeat(64)});await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('所选记录或摘要'));request.mockResolvedValueOnce(e);await click('重试');await vi.waitFor(()=>expect(body().text()).toContain('档案 SHA-256'));expect(body().findAll('.ant-modal')).toHaveLength(1);expect(body().text()).toContain('未校准');await body().get('.ant-modal-close').trigger('click');await flushPromises();request.mockRejectedValueOnce(new ApiError(404,'not_found','评估记录已到期'));await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('已到期'));user.value={...principal,tenant_id:'foreign'};await flushPromises();expect(body().find('.ant-modal').exists()).toBe(false)
 })
 it('未返回的详情在关闭、卸载和切换页签后丢弃',async()=>{
  const e=await record();request.mockResolvedValue({items:[e],next_cursor:''});const router=createRouter({history:createMemoryHistory(),routes:[{path:'/models',component:defineComponent({render:()=>h('div')})}]});await router.push('/models?view=evaluations');await router.isReady();const w=mount(ModelsView,{attachTo:document.body,global:{plugins:[registerAnt,router]}});await flushPromises();expect(w.text()).toContain('评估记录');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('查看');await flushPromises();const signal=request.mock.lastCall?.[1].signal as AbortSignal;await click('决策策略');late.resolve(e);await flushPromises();expect(signal.aborted).toBe(true);expect(router.currentRoute.value.query.view).toBe('policies');expect(body().find('.ant-modal').exists()).toBe(false)
 })
 it('未知提交复用同一键；服务端明确拒绝后允许重新提交',async()=>{
  const e=await record(),j=await source();const w=mount(DecisionPolicyEvaluation,{props:{record:e.policy,triageId:j.id},attachTo:document.body,global:{plugins:[registerAnt]}});request.mockResolvedValueOnce(j).mockRejectedValueOnce(new Error('网络中断'));await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('原评估提交结果尚未确认'));const first=request.mock.lastCall?.[1];expect(body().get('#policy-triage-id').attributes('disabled')).toBeDefined();request.mockRejectedValueOnce(new ApiError(409,'conflict','策略修订已改变'));await click('核对原提交');await vi.waitFor(()=>expect(body().text()).toContain('策略修订已改变'));expect(request.mock.lastCall?.[1].headers).toEqual(first.headers);expect(body().get('#policy-triage-id').attributes('disabled')).toBeUndefined();request.mockResolvedValueOnce(j).mockResolvedValueOnce(e);await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain(e.id));expect(request.mock.lastCall?.[1].headers).not.toEqual(first.headers);expect(w.emitted('close')).toBeUndefined()
 })
})
