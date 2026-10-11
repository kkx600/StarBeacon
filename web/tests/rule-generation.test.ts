import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type Component,type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError,ApiClient} from '../packages/shared/src/api'
import type {Principal,ReplaySample,SampleOrigin} from '../packages/shared/src/types'
import {importError,sampleOrigin} from '../packages/shared/src/utils/sample'
import ReplayWorkspace from '../packages/shared/src/components/ReplayWorkspace.vue'
import ReplayResult from '../packages/shared/src/components/ReplayResult.vue'
import RuleGenerationWorkspace from '../platform/src/features/rules/RuleGenerationWorkspace.vue'
import RulesWorkspace from '../platform/src/features/rules/RulesWorkspace.vue'
import {validGenerationRequest,validGenerationPage,validGenerationJob,validGenerationSample,type GenerationJob,type GenerationRequest,type GenerationSummary} from '../platform/src/features/rules/generation'
import {useRuleGeneration} from '../platform/src/features/rules/useRuleGeneration'
import {session} from '../platform/src/session'
import {analysisProvider} from './analysisFixtures'
import {principal,sample,rulePackage,click,button,deferred,closedMessage} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const origin:SampleOrigin={kind:'http_raw',synthetic:true,raw_sha256:'c'.repeat(64),raw_bytes:64,encoder:'http-raw-tcp/1',segment_bytes:1460}
const httpSample:ReplaySample={...sample,id:'sample_raw',name:'request.raw.pcap',origin}
const input:GenerationRequest={description:'检测 HTTP 请求路径，排除健康检查',source:'natural_language',sample_id:'',sample_sha256:'',provider_id:analysisProvider.id,provider_revision:analysisProvider.revision,candidate_count:1,allow_context:true}
const generationID='gen_'+'1'.repeat(32),packageID='aipkg_'+'1'.repeat(32)+'_1000000'
const completed:GenerationJob={id:generationID,request:input,state:'succeeded',cancel_requested:false,template:'suricata-rule/1',evidence:{sample:null,metadata:null,packets:[],limited:false,sha256:'d'.repeat(64)},sids:[1000000],candidates:[{sid:1000000,engine_version:'8.0.7',title:'HTTP 路径检测',rule:'alert http any any -> any any (msg:"path"; http.uri; content:"/api"; sid:1000000; rev:1;)',explanation:'根据输入检测 HTTP URI',risks:['需验证正常业务误报'],references:[],package_id:packageID,sha256:'e'.repeat(64)}],result:{state:'succeeded',code:'completed',usage:{input_tokens:20,output_tokens:40,total_tokens:60},duration_ms:120},created_at:'2026-10-03T00:00:00Z',started_at:'2026-10-03T00:00:01Z',finished_at:'2026-10-03T00:00:02Z',expires_at:'2027-04-01T00:00:00Z'}
const queued:GenerationJob={...completed,state:'queued',candidates:[],result:{state:'queued',code:'awaiting_execution',usage:null,duration_ms:null},started_at:null,finished_at:null}
const summary:GenerationSummary={id:generationID,title:input.description,source:input.source,state:'succeeded',provider_id:input.provider_id,created_at:completed.created_at,cancel_requested:false}
const page={items:[summary],next_cursor:'',model_execution_available:true}
const adopted={...rulePackage,id:packageID,revision:1,sha256:completed.candidates[0]!.sha256,generation_id:generationID,generation_sid:1000000}
function clone<T>(value:T):T{return structuredClone(value)}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/rule-generation/jobs'?page:path==='/models/providers'?{items:[analysisProvider],available:true}:path==='/replay/samples'?{items:[sample,httpSample],available:true}:path==='/rule-packages'?{items:[rulePackage]}:completed));vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(){let state!:ReturnType<typeof useRuleGeneration>;const wrapper=mount(defineComponent({setup(){state=useRuleGeneration();return()=>h('div')}}));return{state,wrapper}}
async function workspace(component:Component=RuleGenerationWorkspace,path='/rules?view=generation'){
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component}]});await router.push(path);await router.isReady()
  const wrapper=mount(component,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return{wrapper,router}
}
async function describeDetection(value:string){const element=document.body.querySelector<HTMLTextAreaElement>('#rule-generation_description')!;element.value=value;element.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
async function consent(){document.body.querySelector<HTMLInputElement>('.ant-modal input[type=checkbox]')!.click();await flushPromises()}

describe('生成数据契约与来源',()=>{
  it('接受合法自然语言、PCAP 与合成 HTTP 来源，不混淆捕获证据',()=>{
    expect(validGenerationRequest(input)).toBe(true);expect(validGenerationSample(sample)).toBe(true);expect(validGenerationSample(httpSample)).toBe(true);expect(validGenerationPage(page)).toBe(true);expect(validGenerationJob(completed)).toBe(true);expect(validGenerationJob(queued)).toBe(true)
    const raw=clone(completed);raw.request={...input,source:'http_raw',sample_id:httpSample.id,sample_sha256:httpSample.sha256};raw.evidence={...raw.evidence,sample:httpSample,metadata:{packets:8},packets:[{packet:4,protocol:'tcp',source_ip:'192.0.2.10',destination_ip:'198.51.100.20',source_port:40000,destination_port:80,payload_hex:'474554',payload_limited:false}]};raw.candidates[0]!.references=[4];expect(validGenerationJob(raw)).toBe(true)
    raw.request.source='pcap';expect(validGenerationJob(raw)).toBe(false);raw.evidence.sample=sample;raw.request.sample_id=sample.id;expect(validGenerationJob(raw)).toBe(true);raw.candidates[0]!.references=[5];expect(validGenerationJob(raw)).toBe(false)
  })
  it.each([
    {description:''},{description:'a'.repeat(4001)},{description:'\u0000request'},{provider_id:'invalid.id'},{provider_revision:0},{provider_revision:Number.MAX_SAFE_INTEGER+1},{candidate_count:0},{candidate_count:4},{allow_context:false},{source:'ftp'},{sample_id:'sample_1'},{sample_sha256:'a'.repeat(64)},
  ])('拒绝不完整或越界生成输入 %j',change=>expect(validGenerationRequest({...input,...change})).toBe(false))
  it('样本摘要、期限、大小与来源元信息均必须完整',()=>{
    for(const change of [{id:'bad.id'},{sha256:'B'.repeat(64)},{size:23},{size:100*1024*1024+1},{size:1.5},{format:'zip'},{created_at:'invalid'},{expires_at:'invalid'},{origin:{...origin,synthetic:false}}, {name:'n'.repeat(201)}])expect(validGenerationSample({...sample,...change})).toBe(false)
    expect(validGenerationRequest({...input,source:'pcap',sample_id:sample.id,sample_sha256:sample.sha256})).toBe(true);expect(validGenerationRequest({...input,source:'pcap',sample_id:'',sample_sha256:'short'})).toBe(false)
  })
  it('拒绝重复历史、未知状态、无效游标和不完整页',()=>{
    for(const value of [null,[],{...page,model_execution_available:null},{...page,next_cursor:'bad.cursor'},{...page,items:[summary,summary]},{...page,items:[{...summary,state:'complete'}]},{...page,items:[{...summary,source:'tls_decrypted'}]},{...page,items:[{...summary,created_at:'invalid'}]},{...page,items:[{...summary,cancel_requested:'false'}]},{...page,items:Array.from({length:21},(_,i)=>({...summary,id:`job_${i}`}))}])expect(validGenerationPage(value)).toBe(false)
  })
  it('拒绝身份、模型结果、候选 SID 和来源不完整的作业',()=>{
    for(const change of [{id:''},{template:'other'},{state:'done'},{cancel_requested:null},{sids:[]},{sids:[999999]},{sids:[2000000]},{result:null},{result:{state:'bad',code:'done'}},{created_at:'bad'},{finished_at:'bad'},{started_at:'bad'}])expect(validGenerationJob({...completed,...change})).toBe(false)
    const duplicate=clone(completed);duplicate.request.candidate_count=2;duplicate.sids=[1000000,1000000];expect(validGenerationJob(duplicate)).toBe(false)
    for(const change of [{sid:1000001},{engine_version:'8.0.6'},{title:'a'.repeat(129)},{rule:'a'.repeat(16385)},{explanation:'a'.repeat(1001)},{package_id:'bad.id'},{sha256:'short'},{risks:null},{risks:Array(9).fill('risk')},{risks:['a'.repeat(501)]},{references:[4]},{references:[4,4]}])expect(validGenerationJob({...completed,candidates:[{...completed.candidates[0]!,...change}]})).toBe(false)
    expect(validGenerationJob({...queued,candidates:completed.candidates})).toBe(false);expect(validGenerationJob({...completed,candidates:[]})).toBe(false)
  })
  it('有界帧引用必须来自当前样本且拒绝缺测摘要',()=>{
    const pcap=clone(completed);pcap.request={...input,source:'pcap',sample_id:sample.id,sample_sha256:sample.sha256};pcap.evidence={...pcap.evidence,sample,metadata:{},packets:[{packet:4,protocol:'udp',source_ip:'2001:db8::1',destination_ip:'2001:db8::2',source_port:1,destination_port:65535,payload_hex:'00ff',payload_limited:true}]};pcap.candidates[0]!.references=[4];expect(validGenerationJob(pcap)).toBe(true)
    for(const change of [{packet:0},{packet:129},{protocol:'http'},{source_ip:'a'.repeat(46)},{source_port:-1},{destination_port:65536},{payload_hex:'abc'},{payload_hex:'a'.repeat(514)},{payload_limited:null}])expect(validGenerationJob({...pcap,evidence:{...pcap.evidence,packets:[{...pcap.evidence.packets[0]!,...change}]}})).toBe(false)
    for(const change of [{sha256:'short'},{limited:null},{metadata:null},{sample:null},{sample:{...sample,id:'other'}},{sample:{...sample,sha256:'f'.repeat(64)}},{packets:[pcap.evidence.packets[0],pcap.evidence.packets[0]]}])expect(validGenerationJob({...pcap,evidence:{...pcap.evidence,...change}})).toBe(false)
    expect(validGenerationJob({...completed,evidence:{...completed.evidence,metadata:{}}})).toBe(false)
  })
})

describe('生成请求与持久结果',()=>{
  it('历史读取失败可恢复，加载更多去重，旧响应不能覆盖新列表',async()=>{
    request.mockRejectedValueOnce('offline');const{state}=host();await flushPromises();expect(state.error.value).toBe('规则生成记录读取失败')
    request.mockResolvedValueOnce({...page,next_cursor:'older'});await state.refresh();expect(state.next.value).toBe('older')
    request.mockResolvedValueOnce({...page,items:[summary,{...summary,id:'gen_older'}]});await state.refresh('older',true);expect(state.items.value.map(row=>row.id)).toEqual([generationID,'gen_older'])
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const first=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;request.mockResolvedValueOnce({...page,items:[]});await state.refresh();old.resolve(page);await first;expect(signal.aborted).toBe(true);expect(state.items.value).toEqual([])
    request.mockResolvedValueOnce({items:'invalid'});await state.refresh();expect(state.error.value).toContain('未能完整返回')
  })
  it('未知提交锁定原输入并使用同一请求键确认，明确拒绝后可修改',async()=>{
    const{state}=host();await flushPromises();request.mockRejectedValueOnce(new ApiError(0,'network_unavailable','连接中断'));expect(await state.submit(input)).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers['Idempotency-Key']
    const count=request.mock.calls.length;await state.submit({...input,description:'其他检测'});expect(request.mock.calls).toHaveLength(count);expect(state.actionError.value).toContain('确认原请求')
    request.mockResolvedValueOnce(queued);expect((await state.confirm())?.id).toBe(generationID);expect(state.unconfirmed.value).toBe(false);expect(request.mock.calls.filter(call=>call[1]?.method==='POST').map(call=>call[1].headers['Idempotency-Key'])).toEqual([key,key]);await flushPromises()
    request.mockRejectedValueOnce(new ApiError(409,'generation_conflict','修订发生变化'));await state.submit(input);expect(state.unconfirmed.value).toBe(false);expect(state.actionError.value).toContain('修订发生变化');expect(await state.confirm()).toBeUndefined()
  })
  it('响应损坏、输入错配及超时均保留原请求，重复提交和页面离开不会产生迟到结果',async()=>{
    const{state,wrapper}=host();await flushPromises();await state.submit({...input,allow_context:false});expect(state.actionError.value).toContain('数据使用许可')
    request.mockResolvedValueOnce({...queued,request:{...input,description:'other'}});await state.submit(input);expect(state.unconfirmed.value).toBe(true)
    request.mockRejectedValueOnce(new ApiError(408,'timeout','超时'));await state.confirm();expect(state.unconfirmed.value).toBe(true)
    const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const op=state.confirm();const count=request.mock.calls.length;expect(await state.submit(input)).toBeUndefined();expect(request.mock.calls).toHaveLength(count)
    const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);waiting.resolve(queued);expect(await op).toBeUndefined();expect(state.selected.value).toBeNull();expect(await state.submit(input)).toBeUndefined()
  })
  it('详情刷新验证身份且忽略旧请求，失败保留已确认结果',async()=>{
    const{state}=host();await flushPromises();await state.load(generationID);expect(state.selected.value?.state).toBe('succeeded')
    request.mockResolvedValueOnce({...completed,id:'other'});await state.load(generationID);expect(state.detailError.value).toContain('未能完整返回');expect(state.selected.value?.id).toBe(generationID)
    const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const op=state.load(generationID);const signal=request.mock.lastCall?.[1].signal as AbortSignal;request.mockResolvedValueOnce({...completed,id:'gen_other'});await state.load('gen_other');old.resolve(completed);await op;expect(signal.aborted).toBe(true);expect(state.selected.value?.id).toBe('gen_other');state.clear();expect(state.selected.value).toBeNull()
    request.mockRejectedValueOnce('offline');await state.load(generationID);expect(state.detailError.value).toBe('规则生成结果读取失败')
  })
  it('采纳必须对应成功候选与来源，错配结果不显示保存成功',async()=>{
    const{state}=host();await flushPromises();expect(await state.adopt(completed.candidates[0]!)).toBeUndefined();await state.load(generationID)
    expect(await state.adopt({...completed.candidates[0]!,sid:1000001})).toBeUndefined();request.mockResolvedValueOnce({...adopted,generation_id:'other'});expect(await state.adopt(completed.candidates[0]!)).toBeUndefined();expect(state.actionError.value).toContain('采纳结果未能核对')
    request.mockResolvedValueOnce(adopted);expect(await state.adopt(completed.candidates[0]!)).toEqual(adopted);expect(request.mock.lastCall?.[1].body).toEqual({sid:1000000})
    request.mockRejectedValueOnce('offline');await state.adopt(completed.candidates[0]!);expect(state.actionError.value).toBe('规则采纳结果未确认')
  })
  it('取消请求验证回执，读取失败和页面离开不宣称已取消',async()=>{
    const{state,wrapper}=host();await flushPromises();request.mockResolvedValueOnce({...queued,state:'cancelled',cancel_requested:true,result:{state:'cancelled',code:'cancelled_before_execution',usage:null}});await state.cancel(generationID);expect(state.selected.value?.state).toBe('cancelled');await flushPromises()
    request.mockResolvedValueOnce({...queued,id:'wrong'});await state.cancel(generationID);expect(state.actionError.value).toContain('取消结果未能完整返回')
    request.mockRejectedValueOnce('offline');await state.cancel(generationID);expect(state.actionError.value).toBe('取消请求未确认')
    const op=deferred<unknown>();request.mockReturnValueOnce(op.promise);const action=state.cancel(generationID);expect(await state.cancel(generationID)).toBeUndefined();const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);op.resolve(queued);await action;expect(state.selected.value?.state).toBe('cancelled')
  })
  it('活动作业有限轮询，终态停轮询，连续错误退避后允许手动恢复',async()=>{
    vi.useFakeTimers();request.mockResolvedValue({...page,items:[{...summary,state:'queued'}]});const{state,wrapper}=host();await flushPromises();request.mockImplementation((path:string)=>Promise.resolve(path===`/rule-generation/jobs/${generationID}`?queued:{...page,items:[{...summary,state:'queued'}]}));await state.load(generationID)
    await vi.advanceTimersByTimeAsync(3000);await flushPromises();expect(request.mock.calls.filter(call=>call[0]===`/rule-generation/jobs/${generationID}`).length).toBeGreaterThan(1)
    request.mockImplementation((path:string)=>Promise.resolve(path===`/rule-generation/jobs/${generationID}`?completed:page));await vi.advanceTimersByTimeAsync(3000);await flushPromises();await vi.advanceTimersByTimeAsync(3000);const count=request.mock.calls.length;await vi.advanceTimersByTimeAsync(9000);expect(request.mock.calls).toHaveLength(count)
    request.mockRejectedValue('offline');await state.refresh();await vi.advanceTimersByTimeAsync(5000);await flushPromises();await vi.advanceTimersByTimeAsync(10000);await flushPromises();const failures=request.mock.calls.length;await vi.advanceTimersByTimeAsync(20000);expect(request.mock.calls).toHaveLength(failures);request.mockResolvedValue(page);await state.refresh();expect(state.error.value).toBe('');wrapper.unmount()
  })
})

describe('规则生成页面操作',()=>{
  it('规则工作台按页签提供单一业务表格，查看账号不能进入生成',async()=>{
    const{wrapper,router}=await workspace(RulesWorkspace);expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('AI 规则生成');await click('规则包');expect(router.currentRoute.value.query.view).toBeUndefined();expect(wrapper.findAll('.ant-table')).toHaveLength(1)
    wrapper.unmount();(session.current as ShallowRef<Principal|null>).value={...principal,role:'viewer'};const viewer=await workspace(RulesWorkspace);expect(viewer.wrapper.text()).not.toContain('AI 规则生成');expect(request.mock.calls.filter(call=>call[0]==='/rule-generation/jobs')).toHaveLength(1)
  })
  it('无数据、不可用与历史错误都有明确恢复入口',async()=>{
    request.mockResolvedValueOnce({...page,items:[],model_execution_available:false});const{wrapper}=await workspace();expect(wrapper.text()).toContain('暂无规则生成记录');expect(button('生成规则').disabled).toBe(true);expect(wrapper.text()).toContain('模型执行服务暂不可用')
    request.mockRejectedValueOnce(new Error('队列信息不可读'));await click('刷新记录');expect(wrapper.text()).toContain('队列信息不可读');request.mockResolvedValueOnce(page);await click('重试');expect(wrapper.text()).toContain(input.description)
  })
  it('模型、检测说明与本次许可都必填，已受理作业进入结果而不直接发布',async()=>{
    const{wrapper}=await workspace();await click('生成规则');await click('提交生成');expect(document.body.textContent).toContain('填写不超过');await describeDetection(input.description);await click('提交生成');expect(document.body.textContent).toContain('请选择已启用')
    await wrapper.findAllComponents(Select)[0]!.setValue(analysisProvider.id,'value');await click('提交生成');expect(document.body.textContent).toContain('请确认本次检测说明');await consent()
    request.mockResolvedValueOnce(queued);await click('提交生成');expect(document.body.textContent).toContain('规则生成结果');expect(document.body.textContent).toContain('等待生成');expect(document.body.textContent).not.toContain('采纳为规则包');expect(request.mock.calls.find(call=>call[1]?.method==='POST')?.[1].body).toEqual(input)
    request.mockResolvedValueOnce(completed);await click('刷新结果');expect(document.body.textContent).toContain('HTTP 路径检测');expect(document.body.textContent).toContain('需验证正常业务误报');expect(document.body.querySelector('.cm-content')?.getAttribute('contenteditable')).toBe('false')
    request.mockResolvedValueOnce(adopted);await click('采纳为规则包');expect(wrapper.emitted('adopted')?.[0]?.[0]).toEqual(adopted);expect(document.body.textContent).toContain('候选已保存为规则包');expect(button('采纳为规则包').disabled).toBe(true)
  })
  it('材料来源筛选样本，切换目标重置许可，并提供导入入口',async()=>{
    const{wrapper}=await workspace();await click('生成规则');document.body.querySelector<HTMLInputElement>('input[value=http_raw]')!.click();await flushPromises();const selects=wrapper.findAllComponents(Select);expect(selects[0]!.props('options')).toEqual([{value:httpSample.id,label:expect.stringContaining(httpSample.name)}]);expect(document.body.textContent).toContain('HTTP Raw 为合成样本')
    await describeDetection(input.description);await selects[1]!.setValue(analysisProvider.id,'value');await consent();await click('提交生成');expect(document.body.textContent).toContain('请选择尚在保留期');await selects[0]!.setValue(httpSample.id,'value');selects[0]!.vm.$emit('change',httpSample.id);await flushPromises();expect(document.body.querySelector<HTMLInputElement>('input[type=checkbox]')?.checked).toBe(false)
    document.body.querySelector<HTMLInputElement>('input[value=pcap]')!.click();await flushPromises();expect(wrapper.findAllComponents(Select)[0]!.props('options')).toEqual([{value:sample.id,label:expect.stringContaining(sample.name)}]);await click('管理与导入重放样本');expect(wrapper.emitted('samples')).toHaveLength(1)
  })
  it('选项读取失败可以重试，离开页面取消读取，空模型引导配置',async()=>{
    const{wrapper}=await workspace();request.mockRejectedValueOnce('offline');await click('生成规则');expect(document.body.textContent).toContain('生成选项读取失败');request.mockImplementation((path:string)=>Promise.resolve(path==='/models/providers'?{items:[],available:false}: {items:[]}));await click('重试');expect(document.body.textContent).toContain('暂无可用模型')
    await click('关闭');const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);await click('生成规则');const signal=request.mock.calls.findLast(call=>call[0]==='/models/providers')?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve({items:[],available:true});await flushPromises()
  })
  it('提交结果未知时锁定输入，确认原请求后恢复同一作业',async()=>{
    const{wrapper}=await workspace();await click('生成规则');await describeDetection(input.description);await wrapper.findAllComponents(Select)[0]!.setValue(analysisProvider.id,'value');await consent();request.mockRejectedValueOnce(new Error('连接未确认'));await click('提交生成');expect(document.body.textContent).toContain('输入已锁定');expect(document.body.querySelector<HTMLTextAreaElement>('textarea')?.disabled).toBe(true);expect(button('生成规则').disabled).toBe(true)
    const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];request.mockResolvedValueOnce(queued);await click('确认原请求');expect(request.mock.calls.filter(call=>call[1]?.method==='POST').map(call=>call[1].headers['Idempotency-Key'])).toEqual([key,key]);expect(document.body.textContent).toContain('规则生成结果')
  })
  it('详情读取失败重试同一作业，未知调用与取消状态准确呈现',async()=>{
    await workspace();request.mockRejectedValueOnce(new Error('结果读取中断'));await click('查看结果');expect(document.body.textContent).toContain('结果读取中断');request.mockResolvedValueOnce({...completed,state:'uncertain',candidates:[],result:{state:'uncertain',code:'provider_result_unknown',usage:null,duration_ms:null}});await click('重试');expect(request.mock.lastCall?.[0]).toBe('/rule-generation/jobs/'+generationID);expect(document.body.textContent).toContain('提供方可能已执行请求');expect(document.body.textContent).not.toContain('采纳为规则包')
    request.mockResolvedValueOnce({...queued,state:'running',cancel_requested:true,result:{state:'running',code:'request_in_progress',usage:null}});await click('刷新结果');expect(button('取消请求已提交').disabled).toBe(true);expect(document.body.textContent).toContain('未返回用量')
  })
})

describe('HTTP Raw 二进制导入与结果提示',()=>{
  it('文件边界与来源契约拒绝伪造，导入不按文件后缀推断捕获证据',()=>{
    expect(importError(undefined,'pcap')).toContain('PCAP');expect(importError(undefined,'http_raw')).toContain('HTTP Raw');expect(importError(new File([],'empty.raw'),'http_raw')).toContain('1 字节');expect(importError(new File([new Uint8Array(24)],'a.pcap'),'pcap')).toBe('')
    const large=new File([],'large.raw');Object.defineProperty(large,'size',{value:2*1024*1024+1});expect(importError(large,'http_raw')).toContain('2 MiB');expect(importError(new File(['GET / HTTP/1.1\r\n\r\n'],'a.raw'),'http_raw')).toBe('');expect(sampleOrigin(origin)).toEqual(origin)
    for(const value of [null,[],{}, {...origin,kind:'pcap'}, {...origin,synthetic:false},{...origin,raw_sha256:'X'.repeat(64)},{...origin,raw_bytes:0},{...origin,raw_bytes:1.5},{...origin,raw_bytes:2*1024*1024+1},{...origin,encoder:'other'},{...origin,segment_bytes:1500}])expect(sampleOrigin(value)).toBeUndefined()
  })
  it('平台与采集器共用文件模式，切换来源清除旧文件且请求字节原样上传',async()=>{
    const api=new ApiClient('/test');api.request=request;request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?{items:[httpSample],available:true}:{items:[]}));const wrapper=mount(ReplayWorkspace,{props:{api,local:true},global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('HTTP Raw 合成样本');await click('导入样本');document.body.querySelector<HTMLInputElement>('input[value=http_raw]')!.click();await flushPromises();await click('上传样本');expect(document.body.textContent).toContain('请选择 HTTP Raw 文件')
    const raw=new File([new Uint8Array([0x47,0x45,0x54,0,255,13,10])],'request.raw');const file=document.body.querySelector<HTMLInputElement>('#replay-file')!;Object.defineProperty(file,'files',{value:[raw],configurable:true});file.dispatchEvent(new Event('change',{bubbles:true}));await flushPromises();request.mockResolvedValueOnce(httpSample);await click('上传样本');expect(request.mock.calls.find(call=>call[0]==='/replay/samples/http')?.[1].file).toBe(raw)
    await click('重放测试');expect(document.body.textContent).toContain('TCP 握手、地址及时间由离线封装生成')
  })
  it('结果区分合成握手和真实观测，旧回执没有来源时不补造证据',async()=>{
    const wrapper=mount(ReplayResult,{props:{result:{replay:'completed',sample_origin:origin,sample_metadata:{tcp_handshake:{assessed_flows:1,complete_handshakes:1,incomplete_flows:0,limited:false}}}},global:{plugins:[registerAnt]}});expect(wrapper.text()).toContain('合成 TCP 握手观测');expect(wrapper.text()).toContain('HTTP Raw 来源');expect(wrapper.text()).toContain('无合成 HTTP 响应');expect(wrapper.text()).toContain(origin.raw_sha256)
    await wrapper.setProps({result:{replay:'completed',sample_origin:{...origin,raw_bytes:0}}});expect(wrapper.text()).not.toContain('HTTP Raw 来源');expect(wrapper.text()).not.toContain('合成样本')
  })
})
