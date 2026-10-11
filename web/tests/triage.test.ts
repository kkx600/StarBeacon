import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {Select,Modal,message} from 'ant-design-vue'
import {ApiError} from '../packages/shared/src/api'
import {registerAnt} from '../packages/shared/src/ant'
import type {Alert,Principal} from '../packages/shared/src/types'
import AlertTriage from '../platform/src/features/alerts/AlertTriage.vue'
import AlertDetail from '../platform/src/features/alerts/AlertDetail.vue'
import {validTriageRequest,validTriageAnswer,validTriageJob,validTriagePage,validTriageProviders,type TriageJob} from '../platform/src/features/alerts/triage'
import {useAlertTriage} from '../platform/src/features/alerts/useAlertTriage'
import {session} from '../platform/src/session'
import {router} from '../platform/src/router'
import {triageEvent,triageDigest,triageInput,triageJob,triageQueued,triageSummary,triagePage} from './triageFixtures'
import {analysisProvider} from './analysisFixtures'
import {principal,click,button,deferred,closedMessage} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const props={eventId:triageEvent,digest:triageDigest},global={plugins:[registerAnt]}
const pagePath='/alerts/'+triageEvent+'/triage?sha256='+triageDigest,detailPath='/alert-triage/jobs/'+triageJob.id
const clone=<T,>(v:T):T=>structuredClone(v)
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation((path:string,options?:{method?:string})=>Promise.resolve(path==='/models/providers'?{items:[analysisProvider],available:true}:path.startsWith('/alerts/')&&options?.method!=='POST'?triagePage:triageJob));vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(){let state!:ReturnType<typeof useAlertTriage>;const wrapper=mount(defineComponent({setup(){state=useAlertTriage(triageEvent,triageDigest);return()=>h('div')}}));return{state,wrapper}}
async function workspace(){const wrapper=mount(AlertTriage,{props,global,attachTo:document.body});await flushPromises();return wrapper}
async function fill(wrapper:ReturnType<typeof mount>){await wrapper.findAllComponents(Select)[1]!.setValue(analysisProvider.id,'value');const note=document.body.querySelector<HTMLTextAreaElement>('textarea[aria-label="模型研判说明"]')!,consent=document.body.querySelector<HTMLInputElement>('input[type="checkbox"]')!;note.value=triageInput.note;note.dispatchEvent(new Event('input',{bubbles:true}));consent.click();await flushPromises()}

describe('模型研判证据契约',()=>{
 it('请求、所有者分页及模型选项拒绝无效身份与不完整响应',()=>{
  expect(validTriageRequest(triageInput)).toBe(true);expect(validTriagePage(triagePage)).toBe(true);expect(validTriageProviders({items:[analysisProvider],available:true})).toBe(true)
  for(const value of [null,[],{...triageInput,event_id:'bad/id'},{...triageInput,raw_sha256:'A'.repeat(64)},{...triageInput,provider_id:''},{...triageInput,provider_revision:0},{...triageInput,provider_revision:Number.MAX_SAFE_INTEGER+1},{...triageInput,note:'文'.repeat(2001)},{...triageInput,note:'\u0000'},{...triageInput,allow_context:false}])expect(validTriageRequest(value)).toBe(false)
  for(const value of [null,{...triagePage,items:[triageSummary,triageSummary]},{...triagePage,items:[{...triageSummary,state:'foreign'}]},{...triagePage,next_cursor:'wrong'},{...triagePage,model_execution_available:'true'}])expect(validTriagePage(value)).toBe(false)
  for(const value of [null,{items:[analysisProvider,analysisProvider],available:true},{items:[{...analysisProvider,revision:0}],available:true},{items:[{...analysisProvider,name:''}],available:true},{items:[],available:'true'}])expect(validTriageProviders(value)).toBe(false)
 })
 it('成功结论必须引用真实事实，评分和建议不具有处置权限',()=>{
  const answer=triageJob.answer!,evidence=triageJob.evidence
  expect(validTriageAnswer(answer,evidence)).toBe(true)
  for(const value of [null,{...answer,verdict:'toString'},{...answer,outcome:'success'},{...answer,outcome:'prevented'},{...answer,confidence:NaN},{...answer,confidence:Infinity},{...answer,confidence:1.1},{...answer,confidence:-0.1},{...answer,needs_review:false},{...answer,reason:''},{...answer,reason:'文'.repeat(2001)},{...answer,references:['missing']},{...answer,references:[]},{...answer,references:['rule.id','rule.id']},{...answer,counter_evidence:null},{...answer,missing:Array(9).fill('missing')},{...answer,verdict:'suspicious',outcome:'attempt'},{...answer,verdict:'false_positive',outcome:'unknown',counter_evidence:[]},{...answer,recommendation:'execute_command'}])expect(validTriageAnswer(value,evidence)).toBe(false)
  expect(validTriageAnswer({...answer,verdict:'undetermined',outcome:'unknown',references:[]},evidence)).toBe(true)
  expect(validTriageAnswer({...answer,verdict:'false_positive',outcome:'unknown'},evidence)).toBe(true)
  expect(validTriageAnswer({...answer,recommendation:'block_source'},evidence)).toBe(true)
  expect(validTriageAnswer({...answer,recommendation:'block_source',counter_evidence:[]},evidence)).toBe(false)
  expect(validTriageAnswer({...answer,recommendation:'block_source'},{...evidence,facts:evidence.facts.filter(f=>f.id!=='source.ip')})).toBe(false)
 })
 it('作业状态、冻结材料与调用用量必须互相一致',()=>{
  expect(validTriageJob(triageJob)).toBe(true);expect(validTriageJob(triageQueued)).toBe(true)
  const mutations:Array<(v:any)=>void>=[v=>v.id='bad/id',v=>v.template='other',v=>v.confidence_kind='probability',v=>v.created_at='bad',v=>v.started_at='bad',v=>v.finished_at=null,v=>v.evidence.event_id='foreign',v=>v.evidence.raw_sha256='b'.repeat(64),v=>v.evidence.observed_at='',v=>v.evidence.sha256='invalid',v=>v.evidence.limited='yes',v=>v.evidence.facts=[],v=>v.evidence.facts.push(v.evidence.facts[0]),v=>v.evidence.facts[0].id='event.original',v=>v.evidence.facts=v.evidence.facts.filter((f:any)=>f.id!=='sensor.id'),v=>v.evidence.limitations=[],v=>v.result.state='running',v=>v.result.duration_ms=-1,v=>v.result.http_status=99,v=>v.result.returned_model='',v=>v.result.text='unapproved raw output',v=>v.result.usage.total_tokens=61,v=>v.result.usage.input_tokens=1.5,v=>v.answer=null]
  for(const mutation of mutations){const value=clone(triageJob);mutation(value);expect(validTriageJob(value)).toBe(false)}
  expect(validTriageJob({...triageQueued,finished_at:triageJob.finished_at})).toBe(false)
  expect(validTriageJob({...triageQueued,answer:triageJob.answer})).toBe(false)
 })
})

describe('模型研判请求与生命周期',()=>{
 it('模糊提交保留原键，字段顺序不改变幂等语义，已知拒绝解除冻结',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));await state.submit(triageInput);expect(state.unconfirmed.value).toBe(true)
  const first=request.mock.calls.find(c=>c[1]?.method==='POST')!;await state.submit({...triageInput,note:'changed'});expect(state.actionError.value).toContain('先确认原请求')
  const reordered=Object.fromEntries(Object.entries(triageInput).reverse());request.mockResolvedValueOnce({...triageJob,request:reordered});expect(await state.confirm()).toBeDefined();expect(request.mock.calls.filter(c=>c[1]?.method==='POST').map(c=>c[1].headers)).toEqual([first[1].headers,first[1].headers]);expect(state.unconfirmed.value).toBe(false);await flushPromises()
  request.mockRejectedValueOnce(new ApiError(429,'quota','共享调用额度已用尽'));await state.submit(triageInput);expect(state.unconfirmed.value).toBe(false);expect(state.actionError.value).toContain('额度');expect(await state.confirm()).toBeUndefined()
  const count=request.mock.calls.length;await state.submit({...triageInput,event_id:'foreign'});await state.submit({...triageInput,allow_context:false});expect(request.mock.calls).toHaveLength(count)
 })
 it('错配结果保持未知，并发提交和卸载后的响应不能改写状态',async()=>{
  const {state,wrapper}=host();await flushPromises();request.mockResolvedValueOnce({...triageJob,request:{...triageInput,note:'unexpected'}});await state.submit(triageInput);expect(state.unconfirmed.value).toBe(true)
  request.mockRejectedValueOnce('offline');await state.confirm();expect(state.actionError.value).toBe('研判提交结果尚未确认')
  const late=deferred<TriageJob>();request.mockReturnValueOnce(late.promise);const submitting=state.confirm();expect(await state.submit(triageInput)).toBeUndefined();const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(triageJob);await submitting;expect(state.selected.value).toBeNull();await state.refresh();await state.load(triageJob.id);await state.submit(triageInput);await state.cancel(triageJob.id)
 })
 it('列表和详情代次拒绝迟到、跨告警或不完整结果，错误后可重试原作业',async()=>{
  const {state,wrapper}=host();await flushPromises();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const first=state.refresh();await state.refresh();late.resolve({...triagePage,items:[]});await first;expect(state.items.value).toHaveLength(1)
  request.mockResolvedValueOnce({...triagePage,items:[triageSummary,triageSummary]});await state.refresh();expect(state.error.value).toContain('未能完整返回');expect(state.items.value).toHaveLength(1)
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('研判记录读取失败');await state.refresh();expect(state.error.value).toBe('')
  request.mockResolvedValueOnce({...triageJob,request:{...triageInput,event_id:'foreign'}});await state.load(triageJob.id);expect(state.detailError.value).toContain('无法核对');await state.load(triageJob.id);expect(state.selected.value?.id).toBe(triageJob.id)
  request.mockRejectedValueOnce('offline');await state.load(triageJob.id);expect(state.detailError.value).toBe('研判结果读取失败')
  const detail=deferred<TriageJob>();request.mockReturnValueOnce(detail.promise);const reading=state.load(triageJob.id);await state.load(triageJob.id);detail.resolve(triageQueued);await reading;expect(state.selected.value?.state).toBe('succeeded')
  const pending=deferred<TriageJob>();request.mockReturnValueOnce(pending.promise);const stopped=state.load(triageJob.id);wrapper.unmount();pending.resolve(triageQueued);await stopped;expect(state.selected.value?.state).toBe('succeeded')
 })
 it('取消核对作业身份，不把提交取消当作提供方已停止',async()=>{
  const {state,wrapper}=host();await flushPromises();const cancelled:TriageJob={...triageQueued,state:'cancelled',cancel_requested:true,finished_at:triageJob.finished_at,result:{state:'cancelled',code:'cancelled_before_execution',usage:null,duration_ms:null}}
  request.mockResolvedValueOnce(cancelled);await state.cancel(triageJob.id);expect(state.selected.value?.state).toBe('cancelled');await flushPromises()
  request.mockResolvedValueOnce({...cancelled,id:'foreign'});await state.cancel(triageJob.id);expect(state.actionError.value).toContain('取消结果未能核对')
  request.mockRejectedValueOnce('offline');await state.cancel(triageJob.id);expect(state.actionError.value).toBe('取消请求未确认')
  const late=deferred<TriageJob>();request.mockReturnValueOnce(late.promise);const cancelling=state.cancel(triageJob.id);await state.cancel(triageJob.id);const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(triageJob);await cancelling;expect(state.selected.value?.state).toBe('cancelled')
 })
 it('分页限制为一百条并去重，活动作业轮询遇到连续失败后停止',async()=>{
  vi.useFakeTimers();const {state,wrapper}=host();await flushPromises();const rows=Array.from({length:20},(_,i)=>({...triageSummary,id:'triage_'+i}));request.mockResolvedValueOnce({...triagePage,items:rows,next_cursor:rows[19]!.id});await state.refresh();expect(state.next.value).toBe(rows[19]!.id)
  request.mockResolvedValueOnce({...triagePage,items:[rows[19],{...triageSummary,id:'triage_more'}]});await state.refresh(state.next.value);expect(state.items.value).toHaveLength(21)
  request.mockImplementation((path:string)=>Promise.resolve(path===detailPath?triageQueued:{...triagePage,items:[{...triageSummary,state:'queued'}]}));await state.refresh();await state.load(triageJob.id);await vi.advanceTimersByTimeAsync(3000);await flushPromises();expect(request.mock.calls.filter(c=>c[0]===detailPath).length).toBeGreaterThan(1)
  request.mockImplementation((path:string)=>Promise.resolve(path===detailPath?triageJob:triagePage));await vi.advanceTimersByTimeAsync(6000);await flushPromises();const terminal=request.mock.calls.length;await vi.advanceTimersByTimeAsync(9000);expect(request.mock.calls).toHaveLength(terminal)
  request.mockRejectedValue('offline');await state.refresh();await vi.advanceTimersByTimeAsync(5000);await flushPromises();await vi.advanceTimersByTimeAsync(10000);await flushPromises();const failures=request.mock.calls.length;await vi.advanceTimersByTimeAsync(20000);expect(request.mock.calls).toHaveLength(failures);request.mockResolvedValue(triagePage);await state.refresh();expect(state.error.value).toBe('');wrapper.unmount()
 })
})

describe('告警模型研判交互',()=>{
 it('管理员从告警详情携带真实标识与摘要建立事件，只读账号没有操作入口',async()=>{
  const navigate=vi.spyOn(router,'push').mockResolvedValue(undefined)
  const alert:Alert={event_id:triageEvent,tenant_id:principal.tenant_id,sensor_id:'probe_owned','@timestamp':triageJob.created_at,observed_at:triageJob.created_at,received_at:triageJob.created_at,raw_sha256:triageDigest,source_offset:'0',sequence:'1',source:{},destination:{},network:{},http:{},rule:{id:'1000999'},suricata:{},severity:'high',event:{kind:'alert',original:''},evidence_status:'unavailable'}
  const wrapper=mount(AlertDetail,{props:{alert},global,attachTo:document.body});await flushPromises();await click('建立事件调查');expect(navigate).toHaveBeenCalledWith({path:'/incidents',query:{alert_id:triageEvent,sha256:triageDigest}});expect(wrapper.emitted('close')).toHaveLength(1)
  ;(session.current as ShallowRef<Principal|null>).value={...principal,role:'viewer'};await flushPromises();expect(document.body.textContent).not.toContain('建立事件调查')
 })
 it('保持无业务表格布局，明确本次数据许可、模型自评分和真实引用',async()=>{
  const wrapper=await workspace();expect(wrapper.findAll('.ant-table')).toHaveLength(0);expect(button('提交模型研判').disabled).toBe(true);await fill(wrapper);await click('提交模型研判');expect(request.mock.calls.find(c=>c[1]?.method==='POST')?.[1].body).toEqual(triageInput);expect(message.success).toHaveBeenCalledWith('模型研判作业已提交');expect(wrapper.text()).toContain('模型自评分 87.0%');expect(wrapper.text()).toContain('未经校准');expect(wrapper.text()).toContain('/owned-validation');expect(wrapper.text()).toContain('1000999');expect(wrapper.text()).toContain('100 ms');expect(wrapper.text()).toContain('输入 20 / 输出 40');expect(wrapper.text()).not.toContain('执行封禁')
  expect(wrapper.findAll('.ant-table')).toHaveLength(0);await click('刷新模型');await click('刷新结果')
 })
 it('未知提交锁定详情关闭与输入，按原键确认后恢复操作',async()=>{
  const alert:Alert={event_id:triageEvent,tenant_id:principal.tenant_id,sensor_id:'probe_owned','@timestamp':triageJob.created_at,observed_at:triageJob.created_at,received_at:triageJob.created_at,raw_sha256:triageDigest,source_offset:'0',sequence:'1',source:{},destination:{},network:{},http:{},rule:{id:'1000999'},suricata:{},severity:'high',event:{kind:'alert',original:''},evidence_status:'unavailable'}
  const wrapper=mount(AlertDetail,{props:{alert},global,attachTo:document.body});await flushPromises();await click('模型研判');await flushPromises();await fill(wrapper);request.mockRejectedValueOnce(new Error('请求连接中断'));await click('提交模型研判');expect(document.body.textContent).toContain('提交结果尚未确认');expect(wrapper.getComponent(Modal).props('closable')).toBe(false);expect((document.body.querySelector('textarea[aria-label="模型研判说明"]') as HTMLTextAreaElement).disabled).toBe(true)
  const key=request.mock.calls.find(c=>c[1]?.method==='POST')?.[1].headers;await click('确认提交结果');expect(request.mock.calls.filter(c=>c[1]?.method==='POST').map(c=>c[1].headers)).toEqual([key,key]);expect(wrapper.getComponent(Modal).props('closable')).toBe(true);expect(message.success).toHaveBeenCalledWith('研判提交结果已确认')
 })
 it('无数据、不可用与模型读取失败均保留恢复入口',async()=>{
  request.mockImplementation((path:string)=>path==='/models/providers'?Promise.reject(new Error('凭据服务不可读')):Promise.resolve({...triagePage,items:[],model_execution_available:false}));const wrapper=await workspace();expect(wrapper.text()).toContain('暂无模型研判记录');expect(wrapper.text()).toContain('暂不能提交研判');expect(wrapper.text()).toContain('凭据服务不可读');expect(button('提交模型研判').disabled).toBe(true)
  request.mockImplementation((path:string)=>Promise.resolve(path==='/models/providers'?{items:[],available:true}:triagePage));await click('刷新模型');expect(wrapper.text()).toContain('尚无可用模型');await click('刷新记录');expect(wrapper.text()).not.toContain('暂不能提交研判')
  request.mockResolvedValueOnce({items:[{...analysisProvider,revision:0}],available:true});await click('刷新模型');expect(wrapper.text()).toContain('模型配置未能完整返回')
 })
 it('详情失败重试同一记录，未知计费与已登记取消均准确呈现',async()=>{
  const wrapper=await workspace();request.mockRejectedValueOnce(new Error('结果不可读'));await wrapper.findAllComponents(Select)[0]!.setValue(triageJob.id,'value');await flushPromises();expect(wrapper.text()).toContain('结果不可读')
  request.mockResolvedValueOnce({...triageJob,state:'uncertain',answer:null,result:{state:'uncertain',code:'provider_result_unknown',usage:null,duration_ms:null}});await click('重试');expect(request.mock.lastCall?.[0]).toBe(detailPath);expect(wrapper.text()).toContain('费用可能已产生');expect(wrapper.text()).toContain('未获得实际调用耗时');expect(wrapper.text()).not.toContain('模型自评分 87')
  request.mockResolvedValueOnce({...triageQueued,state:'running',cancel_requested:true,result:{state:'running',code:'request_in_progress',usage:null,duration_ms:null}});await click('刷新结果');expect(wrapper.text()).toContain('取消请求已登记');expect(button('取消研判').disabled).toBe(true)
 })
})
