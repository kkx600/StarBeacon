import {webcrypto,randomUUID} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import {Form,InputNumber,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {principal,deferred,click} from './fixtures'
import {triageJob} from './triageFixtures'
import {orderedPolicy,policyChangeError,validPolicyDefinition,validPolicy,validPolicyPage,validPolicyReceipt,validPolicyValidation,validShadowResult,type PolicyChange,type PolicyDefinition,type PolicyRecord,type PolicyResult} from '../platform/src/features/decisions/decisionPolicies'
import {useDecisionPolicies} from '../platform/src/features/decisions/useDecisionPolicies'
import DecisionPolicyForm from '../platform/src/features/decisions/DecisionPolicyForm.vue'
import DecisionPolicyEvaluation from '../platform/src/features/decisions/DecisionPolicyEvaluation.vue'
import DecisionPoliciesWorkspace from '../platform/src/features/decisions/DecisionPoliciesWorkspace.vue'
import ModelsView from '../platform/src/views/ModelsView.vue'
import {orderedEvaluation,type EvaluationRecord} from '../platform/src/features/decisions/decisionEvaluations'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const definition=():PolicyDefinition=>({schema_version:'decision-policy.v1',mode:'shadow',expression:'confidence >= threshold && verdict == "confirmed"',threshold:.8,candidate_action:'investigate',max_age_seconds:3600,protected_prefixes:[]})
const input=():PolicyChange=>({id:'policy_owned',expected_revision:0,name:'攻击尝试策略',description:'按需影子验证',active:true,definition:definition()})
async function record(c=input()):Promise<PolicyRecord>{return {tenant_id:principal.tenant_id,id:c.id,revision:c.expected_revision+1,name:c.name,description:c.description,active:c.active,definition:c.definition,definition_sha256:await goJSONDigest(orderedPolicy(c.definition)),created_by:principal.id,created_at:'2026-10-10T00:00:00Z',expires_at:'2027-04-08T00:00:00Z'}}
async function source(){const j=structuredClone(triageJob),e=j.evidence;e.sha256=await goJSONDigest({event_id:e.event_id,raw_sha256:e.raw_sha256,observed_at:e.observed_at,facts:e.facts,limitations:e.limitations,limited:e.limited,sha256:''});return j}
async function report(p:PolicyRecord,j:typeof triageJob):Promise<PolicyResult>{return {schema_version:'decision-shadow.v1',policy_id:p.id,policy_revision:p.revision,definition_sha256:p.definition_sha256,triage_id:j.id,provider_id:j.request.provider_id,provider_revision:j.request.provider_revision,event_id:j.request.event_id,raw_sha256:j.request.raw_sha256,evidence_sha256:j.evidence.sha256,evaluated_at:'2026-10-10T00:00:00Z',status:'matched',confidence:j.answer!.confidence,confidence_kind:'self_reported',candidate_action:p.definition.candidate_action,target_ip:'',execution_authorized:false,reasons:['expression_matched'],limitations:[...j.evidence.limitations,'影子评估不创建通知、研判修改或设备动作','模型自报分数未获得场景校准资格'],cost:7}}
async function archive(p:PolicyRecord,j:typeof triageJob,r?:PolicyResult):Promise<EvaluationRecord>{const e:EvaluationRecord={schema_version:'decision-evaluation.v1',tenant_id:principal.tenant_id,id:'evaluation_owned',created_by:principal.id,expires_at:'2027-04-08T00:00:00Z',policy:p,result:r??await report(p,j),sha256:''};e.sha256=await goJSONDigest(orderedEvaluation(e));return e}
function host(){let state!:ReturnType<typeof useDecisionPolicies>;const wrapper=mount(defineComponent({setup(){state=useDecisionPolicies();return()=>h('div')}}));return{state,wrapper}}
const body=()=>new DOMWrapper(document.body)
function ui(c:Parameters<typeof mount>[0],props:Record<string,unknown>={}):VueWrapper<any>{return mount(c,{props,attachTo:document.body,global:{plugins:[registerAnt]}}) as VueWrapper<any>}
async function finish(w:VueWrapper){await w.findComponent(Form).vm.$emit('finish',{});await flushPromises()}
async function workspace(component=DecisionPoliciesWorkspace,path='/models?view=policies'){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/models',component:defineComponent({render:()=>h('div')})}]});await router.push(path);await router.isReady();const w=mount(component,{attachTo:document.body,global:{plugins:[registerAnt,router]}});await flushPromises();return {w,router}}
beforeEach(()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID})})
describe('影子策略契约与来源',()=>{
 it('校验版本、参数、摘要和分页；表达式语义由服务端检查',async()=>{
  const d=definition(),c=input(),p=await record();expect(validPolicyDefinition(d)).toBe(true);expect(policyChangeError(c)).toBe('');expect(await validPolicy(p,principal.tenant_id)).toBe(true)
  for(const bad of [null,{}, {...d,mode:'automatic'},{...d,expression:''},{...d,expression:'中'.repeat(700)},{...d,threshold:0},{...d,threshold:NaN},{...d,threshold:2},{...d,candidate_action:'execute'},{...d,max_age_seconds:1},{...d,protected_prefixes:['bad']},{...d,protected_prefixes:['192.0.2.0/24','192.0.2.0/24']},{...d,unknown:true}])expect(validPolicyDefinition(bad)).toBe(false)
  for(const bad of [{...c,id:'/'},{...c,expected_revision:1000000},{...c,name:''},{...c,description:'a\nb'},{...c,active:false},{...c,definition:{...d,threshold:0}}])expect(policyChangeError(bad)).not.toBe('')
  for(const bad of [{...p,tenant_id:'other'},{...p,definition_sha256:'0'.repeat(64)},{...p,expires_at:p.created_at}])expect(await validPolicy(bad,principal.tenant_id)).toBe(false)
  expect(await validPolicyReceipt(p,principal.tenant_id,c)).toBe(true);expect(await validPolicyReceipt({...p,revision:2},principal.tenant_id,c)).toBe(false)
  expect(await validPolicyPage({items:[p],next_cursor:''},principal.tenant_id,'','')).toBe(true)
  for(const bad of [null,{}, {items:[p,p],next_cursor:''},{items:[p],next_cursor:p.id},{items:[p],next_cursor:'/'}])expect(await validPolicyPage(bad,principal.tenant_id,'','')).toBe(false)
  expect(await validPolicyPage({items:[p],next_cursor:''},principal.tenant_id,'','false')).toBe(false)
  expect(await validPolicyValidation({valid:true,schema_version:d.schema_version,definition_sha256:p.definition_sha256,execution_authorized:false},d)).toBe(true);expect(await validPolicyValidation({valid:true,execution_authorized:true},d)).toBe(false)
  vi.stubGlobal('crypto',{});await expect(goJSONDigest(d)).rejects.toThrow('摘要')
 })
 it('不接受执行授权、校准宣称、来源改变和不一致状态',async()=>{
  const p=await record(),j=await source(),r=await report(p,j);expect(await validShadowResult(r,p,j)).toBe(true)
  for(const bad of [null,{}, {...r,execution_authorized:true},{...r,confidence_kind:'calibrated'},{...r,confidence:.99},{...r,policy_revision:2},{...r,triage_id:'other'},{...r,evidence_sha256:'0'.repeat(64)},{...r,reasons:[]},{...r,reasons:['execute']},{...r,cost:-1},{...r,limitations:[]},{...r,status:'abstained'},{...r,status:'matched',cost:null}])expect(await validShadowResult(bad,p,j)).toBe(false)
  expect(await validShadowResult({...r,status:'not_matched',reasons:['expression_not_matched']},p,j)).toBe(true)
  expect(await validShadowResult({...r,status:'protected',cost:null,target_ip:'198.51.100.21',reasons:['protected_source']},p,j)).toBe(true)
  expect(await validShadowResult({...r,status:'abstained',confidence:null,cost:null,reasons:['policy_inactive']},p,j)).toBe(true)
  const corrupt=structuredClone(j);corrupt.evidence.facts[0]!.value='changed';expect(await validShadowResult(r,p,corrupt)).toBe(false)
  expect(await validShadowResult({...r,limitations:['changed',...r.limitations.slice(1)]},p,j)).toBe(false)
 })
})
describe('策略目录与原提交确认',()=>{
 it('有界分页、筛选和身份切换不接受迟到响应',async()=>{
  const p=await record(),items=Array.from({length:20},(_,i)=>({...p,id:'policy_'+String(i).padStart(2,'0')}));request.mockResolvedValue({items,next_cursor:items.at(-1)!.id});const {state,wrapper}=host();await vi.waitFor(()=>expect(state.page.value.items).toHaveLength(20));state.next();await flushPromises();expect(state.error.value).toContain('完整');state.previous();await flushPromises()
  request.mockResolvedValue({items:[],next_cursor:''});state.search(' 攻击 ','false');await flushPromises();expect(state.keyword.value).toBe('攻击');state.next();state.previous();expect(state.cursors.value).toEqual([''])
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,tenant_id:'other'};await flushPromises();late.resolve({items:[p],next_cursor:''});await reading;expect(signal.aborted).toBe(true);expect(state.page.value.items).toEqual([]);wrapper.unmount();await state.refresh()
 })
 it('保存输入冻结、未知回执核对和修订冲突分别处理',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const {state}=host();await flushPromises();const c=input(),p=await record();request.mockRejectedValueOnce(new Error('中断'));await state.save(c);expect(state.unconfirmed.value).toBe(true);const first=request.mock.lastCall?.[1];expect(state.draft()?.id).toBe(c.id);state.clearError();await state.save({...c,name:'other'});expect(state.mutationError.value).toContain('原提交')
  request.mockResolvedValueOnce({...p,revision:3});await state.confirm();expect(state.unconfirmed.value).toBe(true);request.mockResolvedValueOnce(p);expect(await state.confirm()).toEqual(p);expect(request.mock.lastCall?.[1].headers).toEqual(first.headers);expect(await state.confirm()).toBeUndefined();state.clearError();expect(state.mutationError.value).toBe('')
  request.mockRejectedValueOnce(new ApiError(409,'conflict','修订变化'));await state.save(c);expect(state.unconfirmed.value).toBe(false);await state.save({...c,name:''});expect(state.mutationError.value).toContain('名称')
 })
 it('提交超时、卸载和错误目录不作为空成功',async()=>{
  request.mockResolvedValue({});const {state,wrapper}=host();await flushPromises();expect(state.error.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toContain('读取失败');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);vi.useFakeTimers();const saving=state.save(input());expect(await state.save(input())).toBeUndefined();await vi.advanceTimersByTimeAsync(30001);late.resolve(await record());await saving;expect(state.unconfirmed.value).toBe(true);vi.useRealTimers()
  const unmounted=deferred<unknown>();request.mockReturnValueOnce(unmounted.promise);const confirm=state.confirm();wrapper.unmount();unmounted.resolve(await record());await confirm;expect(await state.save(input())).toBeUndefined()
 })
})
describe('策略表单、详情与评估交互',()=>{
 it('名称必填，语法回执独立核验，保存不要求伪造评估结果',async()=>{
  const w=ui(DecisionPolicyForm,{record:null,busy:false,unconfirmed:false,error:''});await finish(w);expect(body().text()).toContain('请填写策略名称');await body().find('#policy-name').setValue(' 业务策略 ')
  request.mockImplementation(async(_p,opts)=>({valid:true,schema_version:'decision-policy.v1',definition_sha256:await goJSONDigest(orderedPolicy(opts.body.definition)),execution_authorized:false}));await click('检查表达式');await vi.waitFor(()=>expect(body().text()).toContain('表达式与参数校验通过'));await finish(w);expect(w.emitted('save')?.[0]?.[0]).toMatchObject({name:'业务策略',expected_revision:0,definition:{mode:'shadow'}})
  await body().find('#policy-expression').setValue('confidence > threshold');expect(body().text()).not.toContain('表达式与参数校验通过');request.mockResolvedValueOnce({});await click('检查表达式');await vi.waitFor(()=>expect(body().text()).toContain('回执与当前定义不一致'));await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('无变更、未知提交和卸载期间不能另建动作',async()=>{
  const p=await record(),w=ui(DecisionPolicyForm,{record:p,busy:false,unconfirmed:false,error:''});await finish(w);expect(body().text()).toContain('没有可提交');await w.setProps({unconfirmed:true});await finish(w);expect(w.emitted('save')).toBeUndefined();await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);await w.setProps({unconfirmed:false,error:'修订冲突'});expect(body().text()).toContain('修订冲突');await body().find('#policy-expression').setValue('confidence > threshold');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('检查表达式');w.unmount();late.resolve({});await flushPromises()
 })
 it('空与有数据、检索草稿和单一详情弹窗状态明确',async()=>{
  const p=await record();request.mockResolvedValue({items:[],next_cursor:''});const {w}=await workspace();expect(w.text()).toContain('暂无决策策略');await w.get('input').setValue('missing');await w.get('form').trigger('submit');await flushPromises();expect(w.text()).toContain('没有符合筛选条件');await w.get('input').setValue('');expect(w.text()).toContain('没有符合筛选条件')
  request.mockResolvedValue({items:[p],next_cursor:''});await click('刷新');await vi.waitFor(()=>expect(w.findAll('.ant-table')).toHaveLength(1));request.mockResolvedValueOnce(p);await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('策略 / 修订'));w.findComponent(InputNumber).vm.$emit('update:value',null);await flushPromises();await click('读取');w.findComponent(InputNumber).vm.$emit('input','1');await flushPromises();request.mockResolvedValueOnce({...p,revision:2});await click('读取');await vi.waitFor(()=>expect(body().text()).toContain('策略修订回执'));request.mockResolvedValueOnce(p);await click('重试');await flushPromises();await body().find('.ant-modal-close').trigger('click');await flushPromises();await click('影子评估');expect(body().text()).toContain('执行影子评估');await body().find('.ant-modal-close').trigger('click');await flushPromises();await click('编辑');expect(body().text()).toContain('编辑决策策略');user.value={...principal,role:'viewer'};await flushPromises();expect(body().text()).not.toContain('编辑决策策略');expect(w.text()).not.toContain('创建策略')
 })
 it('表单保存、原提交核对和模型页签保持单一工作区',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const {w,router}=await workspace(ModelsView);expect(w.text()).toContain('决策策略');await click('创建策略');await body().find('#policy-name').setValue('保存策略');request.mockImplementation(async(path,opts)=>opts?.method==='POST'?record(opts.body):({items:[],next_cursor:''}));await finish(w);await vi.waitFor(()=>expect(body().find('.ant-modal').exists()).toBe(false));await click('创建策略');await body().find('#policy-name').setValue('未知策略');request.mockRejectedValueOnce(new Error('中断'));await finish(w);await vi.waitFor(()=>expect(body().text()).toContain('原提交结果尚未确认'));const c=request.mock.calls.filter(call=>call[1]?.method==='POST').at(-1)?.[1].body;expect(c?.name).toBe('未知策略');request.mockResolvedValueOnce(await record(c));await click('核对原提交',document.querySelector('.ant-modal')!);await vi.waitFor(()=>expect(body().find('.ant-modal').exists(),body().text()).toBe(false));await click('MCP服务');expect(router.currentRoute.value.query.view).toBe('mcp');expect(w.text()).not.toContain('暂无决策策略')
 })
 it('评估核对来源、候选与错误，修改标识清空历史结果',async()=>{
  const p=await record(),j=await source(),r=await report(p,j);const w=ui(DecisionPolicyEvaluation,{record:p});await click('执行影子评估');expect(body().text()).toContain('请输入本账号');await body().find('#policy-triage-id').setValue(j.id);request.mockResolvedValueOnce(j).mockResolvedValueOnce(await archive(p,j,r));await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('策略命中 · 未授权执行'));expect(body().text()).toContain('0.870');expect(request.mock.lastCall?.[1].body).toEqual({policy_id:p.id,expected_revision:1,triage_id:j.id})
  await body().find('#policy-triage-id').setValue('triage_other');expect(body().find('[aria-label="影子评估结果"]').exists()).toBe(false);request.mockResolvedValueOnce(j);await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('研判材料回执'));await body().find('#policy-triage-id').setValue(j.id);request.mockResolvedValueOnce(j).mockResolvedValueOnce({...await archive(p,j),result:{...r,execution_authorized:true}});await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('影子评估回执'));const frozen=request.mock.lastCall?.[1];request.mockResolvedValueOnce(await archive(p,j));await click('核对原提交');await vi.waitFor(()=>expect(body().text()).toContain('策略命中'));expect(request.mock.lastCall?.[1].headers).toEqual(frozen.headers);request.mockRejectedValueOnce(new Error('不可访问'));await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('不可访问'));await body().find('.ant-modal-close').trigger('click');expect(w.emitted('close')).toHaveLength(1)
 })
 it('材料未参与与超限状态准确，关闭或迟到响应不覆盖',async()=>{
  const p=await record(),j=await source(),r=await report(p,j);const w=ui(DecisionPolicyEvaluation,{record:p,triageId:j.id});request.mockResolvedValueOnce(j).mockResolvedValueOnce(await archive(p,j,{...r,status:'abstained',confidence:null,cost:null,reasons:['policy_inactive']}));await click('执行影子评估');await vi.waitFor(()=>expect(body().text()).toContain('不参与决策'));expect(body().text()).toContain('未参与评估');expect(body().text()).toContain('未执行表达式');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);await click('执行影子评估');w.unmount();late.resolve(j);await flushPromises();expect(body().find('[aria-label="影子评估结果"]').exists()).toBe(false)
 })
})
