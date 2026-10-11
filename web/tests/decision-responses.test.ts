import {webcrypto,randomUUID} from 'node:crypto'
import {defineComponent,h,shallowRef} from 'vue'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,mount,flushPromises} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message} from 'ant-design-vue'
import {registerAnt} from '@starbeacon/shared/ant.ts'
import {ApiError} from '@starbeacon/shared/api.ts'
import {eligibleDecisionResponse,eligibleResponseSensor,validDecisionResponse,validResponseRequest} from '../platform/src/features/decisions/decisionResponses'
import type {EvaluationRecord} from '../platform/src/features/decisions/decisionEvaluations'
import DecisionResponseDialog from '../platform/src/features/decisions/DecisionResponseDialog.vue'
import DecisionEvaluationsWorkspace from '../platform/src/features/decisions/DecisionEvaluationsWorkspace.vue'
import {responseEvaluation,responseInput,responseReceipt,responseSensor} from './decisionResponseFixtures'
import {principal,click,deferred,closedMessage} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const body=()=>new DOMWrapper(document.body)
async function plugins(){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:defineComponent({render:()=>h('div')})}]});await router.push('/models?view=evaluations');await router.isReady();return [registerAnt,router]}
async function modal(e?:EvaluationRecord){const w=mount(DecisionResponseDialog,{props:{record:e??await responseEvaluation()},global:{plugins:await plugins()},attachTo:document.body});await flushPromises();return w}
async function fill(){await vi.waitFor(()=>expect(body().find('textarea[aria-label="处置操作依据"]').exists()).toBe(true));await body().get('textarea[aria-label="处置操作依据"]').setValue('管理员核对异常通信');await body().get('.ant-modal input[type="checkbox"]').setValue(true)}
async function submit(){await body().get('.ant-modal form').trigger('submit');await flushPromises()}
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.endsWith('/response')?{item:null}:{items:[responseSensor()]}));vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID});vi.spyOn(message,'success').mockImplementation(closedMessage)})
describe('研判处置授权档案',()=>{
 it('回执必须绑定完整原评估、本人和原输入，不能靠受理 ID 证明成功',async()=>{
  const e=await responseEvaluation(),r=await responseReceipt(e);expect(await validDecisionResponse(r,e,principal.tenant_id,principal.id)).toBe(true);expect(await validDecisionResponse(r,e,principal.tenant_id,principal.id,responseInput(e))).toBe(true)
  const bad=[null,{}, {...r,extra:true},{...r,tenant_id:'foreign'},{...r,created_by:'other'},{...r,id:'response_owned'},{...r,created_at:'invalid'},{...r,created_at:'2020-01-01T00:00:00Z'},{...r,expires_at:r.created_at},{...r,evaluation_id:'other'},{...r,evaluation_sha256:'b'.repeat(64)},{...r,policy_id:'other'},{...r,policy_revision:2},{...r,definition_sha256:'b'.repeat(64)},{...r,triage_id:'other'},{...r,evidence_sha256:'b'.repeat(64)},{...r,target_ip:'198.51.100.22'},{...r,task_id:'task_other'},{...r,sha256:'c'.repeat(64)},{...r,request:{...r.request,confirmed:false}},{...r,request:{...r.request,evaluation_sha256:'b'.repeat(64)}}]
  for(const v of bad)expect(await validDecisionResponse(v,e,principal.tenant_id,principal.id)).toBe(false)
  expect(await validDecisionResponse(r,e,principal.tenant_id,principal.id,{...responseInput(e),ttl_seconds:301})).toBe(false)
  expect(await validDecisionResponse(r,{...e,sha256:'a'.repeat(64)},principal.tenant_id,principal.id)).toBe(false)
 })
 it('输入和候选资格拒绝越界期限、未来观测、离线设备及未确认动作',async()=>{
  const e=await responseEvaluation(),input=responseInput(e);expect(validResponseRequest(input)).toBe(true);expect(eligibleDecisionResponse(e)).toBe(true);expect(eligibleResponseSensor(responseSensor())).toBe(true)
  for(const v of [null,[],{}, {...input,extra:true},{...input,evaluation_sha256:'bad'},{...input,sensor_id:'/'},{...input,registration_id:'/'},{...input,connector_id:'/'},{...input,config_sha256:'bad'},{...input,ttl_seconds:29},{...input,ttl_seconds:3601},{...input,ttl_seconds:30.5},{...input,reason:''},{...input,reason:' 前后空格 '},{...input,reason:'理由\n'},{...input,reason:'中'.repeat(501)},{...input,confirmed:false}])expect(validResponseRequest(v)).toBe(false)
  for(const v of [{...e,expires_at:new Date(Date.now()-1).toISOString()},{...e,result:{...e.result,evaluated_at:new Date(Date.now()+60000).toISOString()}},{...e,result:{...e.result,status:'not_matched' as const}},{...e,result:{...e.result,candidate_action:'notify' as const}},{...e,result:{...e.result,target_ip:''}}])expect(eligibleDecisionResponse(v)).toBe(false)
  for(const patch of [{active:false},{status:'offline' as const},{registration_id:'/'},{last_seen:'invalid'},{last_seen:new Date(Date.now()-36000).toISOString()},{last_seen:new Date(Date.now()+31000).toISOString()},{health:{...responseSensor().health,task_capabilities:[]}},{health:{...responseSensor().health,response_connectors:[]}}])expect(!!eligibleResponseSensor({...responseSensor(),...patch})).toBe(false)
 })
})
describe('研判到人工处置的界面',()=>{
 it('原源 IP 不可编辑，明确确认后只提交一次，完整回执显示原授权',async()=>{
  const e=await responseEvaluation(),w=await modal(e);await fill();expect(body().find('input[aria-label="封禁目标 IP"]').exists()).toBe(false)
  const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);body().get('form').trigger('submit');body().get('form').trigger('submit');await flushPromises();const calls=request.mock.calls.filter(v=>v[1]?.method==='POST');expect(calls).toHaveLength(1);expect(calls[0]?.[1].body).toEqual(responseInput(e));expect(calls[0]?.[1].body.target_ip).toBeUndefined()
  pending.resolve(await responseReceipt(e,calls[0]?.[1].body));await vi.waitFor(()=>expect(body().text()).toContain('签名任务'));expect(message.success).toHaveBeenCalledOnce();expect(body().text()).toContain('任务受理不等于');expect(body().find('form').exists()).toBe(false);await click('查看任务记录');expect(w.vm.$router.currentRoute.value.path).toBe('/sensors');expect(w.vm.$router.currentRoute.value.query).toEqual({view:'tasks',task:(await responseReceipt(e)).task_id});w.unmount()
 })
 it('未知提交锁定原输入和键，错误回执不能显示成功，核对复用原键',async()=>{
  const e=await responseEvaluation(),w=await modal(e);await fill();request.mockRejectedValueOnce(new Error('网络断开'));await submit();const original=request.mock.lastCall!;expect(body().text()).toContain('核对原提交');expect(body().get('textarea').attributes('disabled')).toBeDefined()
  request.mockResolvedValueOnce({id:'task_'+'2'.repeat(32)});await submit();expect(message.success).not.toHaveBeenCalled();expect(request.mock.lastCall?.[1].headers).toEqual(original[1].headers)
  request.mockResolvedValueOnce(await responseReceipt(e,original[1].body));await submit();await vi.waitFor(()=>expect(body().text()).toContain('签名任务'));expect(request.mock.lastCall?.[1].body).toEqual(original[1].body);w.unmount()
 })
 it('确定拒绝允许重新确认，未确认的表单不发送任务',async()=>{
  const w=await modal();await vi.waitFor(()=>expect(body().find('form').exists()).toBe(true));await submit();expect(request.mock.calls.filter(v=>v[1]?.method==='POST')).toHaveLength(0);expect(body().text()).toContain('明确确认')
  await fill();request.mockRejectedValueOnce(new ApiError(409,'decision_response_source_changed','策略修订已变化'));await submit();const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];expect(body().get('textarea').attributes('disabled')).toBeUndefined();request.mockRejectedValueOnce(new ApiError(408,'timeout','结果未确认'));await submit();expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).not.toBe(key);expect(body().text()).toContain('核对原提交');w.unmount()
 })
 it('已有授权只读展示，不读取设备、不重新提交',async()=>{
  const e=await responseEvaluation(),r=await responseReceipt(e);request.mockResolvedValueOnce({item:r});const w=await modal(e);await vi.waitFor(()=>expect(body().text()).toContain('签名任务'));expect(request).toHaveBeenCalledTimes(1);expect(body().find('form').exists()).toBe(false);await click('返回');expect(w.emitted('close')).toHaveLength(1)
 })
 it('无就绪设备、读取失败、权限不足和损坏档案显示可核对的状态',async()=>{
  for(const mode of ['empty','offline','malformed','corrupt','failure','viewer'] as const){request.mockReset();if(mode==='viewer')user.value={...principal,role:'viewer'};request.mockImplementation((path:string)=>{if(path.endsWith('/response')){if(mode==='failure')return Promise.reject(new Error('材料服务中断'));return Promise.resolve(mode==='malformed'?{}:mode==='corrupt'?{item:{}}:{item:null})}return Promise.resolve({items:mode==='empty'?[]:[{...responseSensor(),status:'offline'}]})});const w=await modal();await vi.waitFor(()=>expect(body().text()).toMatch(/没有具备|读取不完整|不一致|中断/));expect(body().find('form').exists()).toBe(false);w.unmount();user.value=principal}
 })
 it('账号切换和卸载取消请求，迟到回执不得显示成功',async()=>{
  const e=await responseEvaluation(),w=await modal(e);await fill();const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);await submit();const signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,id:'another_admin'};await flushPromises();expect(signal.aborted).toBe(true);pending.resolve(await responseReceipt(e));await flushPromises();expect(message.success).not.toHaveBeenCalled();w.unmount()
  user.value=principal;const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const other=await modal(e);const readSignal=request.mock.lastCall?.[1].signal as AbortSignal;other.unmount();expect(readSignal.aborted).toBe(true);late.resolve({item:null});await flushPromises()
 })
 it('处置入口沿用单表和单弹窗，切换账号关闭详情',async()=>{
  const e=await responseEvaluation();request.mockImplementation((path:string)=>Promise.resolve(path==='/decision-evaluations/'+e.id?e:path.endsWith('/response')?{item:null}:path.startsWith('/sensors')?{items:[responseSensor()]}:{items:[e],next_cursor:''}));const w=mount(DecisionEvaluationsWorkspace,{global:{plugins:await plugins()},attachTo:document.body});await vi.waitFor(()=>expect(w.findAll('.ant-table')).toHaveLength(1));await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('处置确认'));await click('处置确认');await fill();expect(body().findAll('.ant-modal')).toHaveLength(1);expect(w.findAll('.ant-table')).toHaveLength(1);user.value={...principal,role:'viewer'};await flushPromises();expect(body().find('.ant-modal').exists()).toBe(false)
 })
})
