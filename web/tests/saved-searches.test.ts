import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {flushPromises,mount} from '@vue/test-utils'
import {Checkbox,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {SearchRequest} from '../packages/shared/src/types'
import {canEditSaved,changeError,definitionFromQuery,editSaved,emptyTerms,parserVersion,sameDefinition,savedID,savedWindowLabel,validDefinition,validSavedPage,validSavedQuery,validSavedReceipt,validSavedResolution,type Dataset,type SavedChange,type SavedDefinition,type SavedQuery,type SavedResolution} from '../platform/src/features/search/savedSearch'
import {useSavedSearches} from '../platform/src/features/search/useSavedSearches'
import SaveQueryForm from '../platform/src/features/search/SaveQueryForm.vue'
import QuerySummary from '../platform/src/features/search/QuerySummary.vue'
import SavedSearchTools from '../platform/src/features/search/SavedSearchTools.vue'
import TrafficFilters from '../platform/src/features/traffic/TrafficFilters.vue'
import AlertFilters from '../platform/src/features/alerts/AlertFilters.vue'
import AlertsWorkspace from '../platform/src/features/alerts/AlertsWorkspace.vue'
import TrafficEvents from '../platform/src/features/traffic/TrafficEvents.vue'
import {defaultTrafficFilters,type TrafficQuery} from '../platform/src/features/traffic/traffic'
import {useTraffic} from '../platform/src/features/traffic/useTraffic'
import {useAlerts} from '../platform/src/features/alerts/useAlerts'
import {button,click,deferred,principal} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const global={plugins:[registerAnt]},stamp='2026-10-03T00:00:00Z'
function definition(dataset:Dataset='alerts'):SavedDefinition{return {schema_version:'saved.search.v1',parser_version:parserVersion,dataset,mode:'visual',window:{mode:'relative',hours:24},terms:emptyTerms()}}
function input(dataset:Dataset='alerts'):SavedChange{return {id:'sq_owned',expected_revision:0,expected_generation_id:'',name:'办公出口查询',description:'核对请求行为',visibility:'personal',active:true,definition:definition(dataset)}}
function record(dataset:Dataset='alerts',id='sq_owned'):SavedQuery{return {tenant_id:principal.tenant_id,id,generation_id:'querygen_owned',owner_id:principal.id,revision:1,name:'办公出口查询',description:'核对请求行为',visibility:'personal',active:true,definition:definition(dataset),created_at:stamp,updated_at:stamp,expires_at:null}}
function receipt(value:SavedChange):SavedQuery{return {...record(value.definition.dataset,value.id),...value,generation_id:value.expected_generation_id||'querygen_owned',revision:value.expected_revision+1,expires_at:value.active?null:'2027-04-01T00:00:00Z'}}
function resolution(value=record()):SavedResolution{
 const terms={...value.definition.terms} as Record<string,unknown>
 if(value.definition.dataset==='alerts')for(const key of ['event_kind','sensor_id','sensor_registration_id','source_generation_id','flow_id'])delete terms[key]
 const window=value.definition.window
 return {tenant_id:value.tenant_id,id:value.id,generation_id:value.generation_id,revision:value.revision,definition:structuredClone(value.definition),query:{...terms,start:window.mode==='absolute'?window.start:'2026-10-02T00:00:00.123456789Z',end:window.mode==='absolute'?window.end:'2026-10-03T00:00:00.123456789Z',page:1,page_size:20} as SearchRequest}
}
function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));return {state,wrapper}}
function form(props:Partial<InstanceType<typeof SaveQueryForm>['$props']>={}){return mount(SaveQueryForm,{global,props:{record:null,current:definition(),busy:false,unconfirmed:false,error:'',...props},attachTo:document.body})}
async function field(id:string,value:string){const element=document.getElementById(id) as HTMLInputElement|null;expect(element).not.toBeNull();element!.value=value;element!.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
beforeEach(()=>{request.mockReset();user.value=principal})

describe('保存查询契约与权限',()=>{
 it('区分数据集、模式和窗口，完整保留 uint64 标识与查询来源',()=>{
  expect(savedID('sq_a-1')).toBe(true);for(const value of [null,1,'','bad/id','a'.repeat(129)])expect(savedID(value)).toBe(false)
  const context=definition('context');context.terms={...emptyTerms(),flow_id:'18446744073709551615',sensor_registration_id:'reg_owned',source_generation_id:'gen_owned',source_ip:'2001:0db8::1'};expect(validDefinition(context)).toBe(true)
  expect(validDefinition({...context,mode:'advanced',terms:{...context.terms,filter:'tcp.port == 443'}})).toBe(true)
  const absolute={...definition(),window:{mode:'absolute' as const,start:'2026-10-02T08:00:00+08:00',end:'2026-10-03T08:00:00+08:00'}};expect(validDefinition(absolute)).toBe(true)
  const bad:unknown[]=[null,[],{}, {...context,schema_version:'other'},{...context,parser_version:''},{...context,dataset:'all'},{...context,mode:'script'},{...context,window:{}},{...context,window:{mode:'relative',hours:'24'}},{...context,window:{mode:'relative',hours:1}},{...context,window:{mode:'relative',hours:24,start:stamp}},{...context,window:{mode:'relative',hours:24,end:stamp}},{...context,window:{mode:'absolute',start:stamp,end:stamp}},{...context,window:{mode:'absolute',start:'invalid',end:stamp}},{...context,window:{mode:'absolute',start:'2026-08-01T00:00:00Z',end:stamp}},{...context,window:{mode:'absolute',hours:24,start:'2026-10-02T00:00:00Z',end:stamp}},{...context,terms:{...context.terms,unknown:''}},{...context,terms:{...context.terms,path:1}},{...context,terms:{...context.terms,path:'a\nb'}},{...context,terms:{...context.terms,filter:'a'.repeat(4097)}},{...context,terms:{...context.terms,filter:'tcp'}},{...context,terms:{...context.terms,keyword:'secret'}},{...context,terms:{...context.terms,severity:'high'}}]
  for(const value of bad)expect(validDefinition(value),JSON.stringify(value)).toBe(false)
  for(const key of ['event_kind','sensor_id','sensor_registration_id','source_generation_id','flow_id'])expect(validDefinition({...definition(),terms:{...emptyTerms(),[key]:'x'}})).toBe(false)
  for(const key of ['keyword','source_ip','destination_ip','protocol','method','path','severity'])expect(validDefinition({...definition(),mode:'advanced',terms:{...emptyTerms(),filter:'tcp',[key]:'x'}})).toBe(false)
  for(const [key,max] of [['keyword',256],['path',1024],['protocol',32],['method',16],['source_ip',128]] as const)expect(validDefinition({...definition(),terms:{...emptyTerms(),[key]:'a'.repeat(max+1)}})).toBe(false)
  expect(validDefinition({...definition(),parser_version:'future'})).toBe(true)
  const q={...defaultTrafficFilters(),filter:'tcp',flow_id:'18446744073709551615',start:'2026-10-02T00:00:00Z',end:stamp,page:7,page_size:50};expect(definitionFromQuery('context',q,0)).toMatchObject({mode:'advanced',window:{mode:'absolute',start:q.start,end:q.end},terms:{flow_id:q.flow_id}});expect(definitionFromQuery('context',q,168).window).toEqual({mode:'relative',hours:168})
  expect([savedWindowLabel({mode:'relative',hours:24}),savedWindowLabel({mode:'relative',hours:168}),savedWindowLabel({mode:'relative',hours:720}),savedWindowLabel(absolute.window)]).toEqual(['最近 24 小时','最近 7 天','最近 30 天','固定时间范围'])
 })
 it('保存操作绑定实例、修订和实际输入，拒绝损坏回执及跨账号数据',()=>{
  expect(changeError(input())).toBe('')
  for(const value of [{...input(),id:'bad/id'},{...input(),expected_revision:1000000},{...input(),expected_generation_id:'unexpected'},{...input(),expected_revision:1},{...input(),name:''},{...input(),name:'a\nb'},{...input(),description:'a'.repeat(1001)},{...input(),visibility:'all'},{...input(),active:false},{...input(),definition:{...definition(),schema_version:'other'}},{...input(),definition:{...definition(),parser_version:'future'}}])expect(changeError(value as SavedChange)).not.toBe('')
  const value=record();expect(validSavedQuery(value,principal,'alerts')).toBe(true);expect(validSavedReceipt(value,input(),principal)).toBe(true)
  const changed=editSaved(value);changed.name='已核对查询';expect(validSavedReceipt(receipt(changed),changed,principal)).toBe(true);changed.definition.terms.path='/edited';expect(value.definition.terms.path).toBe('')
  const bad=[{...value,tenant_id:'foreign'},{...value,id:'bad/id'},{...value,generation_id:''},{...value,owner_id:'other'},{...value,revision:0},{...value,name:'  '},{...value,description:'a\nb'},{...value,visibility:'all'},{...value,active:1},{...value,created_at:'invalid'},{...value,updated_at:'2026-10-02T00:00:00Z'},{...value,expires_at:stamp},{...value,active:false,expires_at:null},{...value,active:false,expires_at:stamp}]
  for(const candidate of bad)expect(validSavedQuery(candidate,principal,'alerts')).toBe(false)
  expect(validSavedQuery({...value,active:false,expires_at:'2027-04-01T00:00:00Z'},principal,'alerts')).toBe(true);expect(validSavedQuery(value,principal,'context')).toBe(false)
  expect(validSavedQuery({...value,visibility:'team',owner_id:'other'},principal,'alerts')).toBe(true)
  expect(canEditSaved(value,principal)).toBe(true);expect(canEditSaved({...value,visibility:'team'},{...principal,role:'viewer'})).toBe(false);expect(canEditSaved(value,{...principal,id:'other'})).toBe(false);expect(canEditSaved(value,{...principal,role:'viewer'})).toBe(true)
  for(const candidate of [{...value,id:'sq_other'},{...value,revision:2},{...value,name:'other'},{...value,description:'other'},{...value,visibility:'team'},{...value,active:false,expires_at:'2027-04-01T00:00:00Z'},{...value,definition:{...value.definition,terms:{...emptyTerms(),path:'/other'}}}])expect(validSavedReceipt(candidate,input(),principal)).toBe(false)
  expect(validSavedReceipt({...receipt(editSaved(value)),generation_id:'querygen_other'},editSaved(value),principal)).toBe(false)
 })
 it('目录分页只能前进，团队可见不授予个人查询读取权限',()=>{
  const filter={keyword:'',visibility:'' as const,active:'true' as const},items=Array.from({length:20},(_,i)=>record('alerts','sq_'+String(i).padStart(3,'0')))
  expect(validSavedPage({items,next_cursor:items.at(-1)!.id},principal,'alerts',filter,'')).toBe(true);expect(validSavedPage({items:[],next_cursor:''},principal,'alerts',filter,'')).toBe(true)
  for(const value of [null,{}, {items:[],next_cursor:'bad/id'},{items:items.slice(0,1),next_cursor:items[0]!.id},{items,next_cursor:'sq_other'},{items:[items[0],items[0]],next_cursor:''},{items:[items[1],items[0]],next_cursor:''},{items:[{...record(),owner_id:'other'}],next_cursor:''},{items:[{...record(),active:false,expires_at:'2027-04-01T00:00:00Z'}],next_cursor:''},{items:Array(21).fill(record()),next_cursor:''}])expect(validSavedPage(value,principal,'alerts',filter,'')).toBe(false)
  expect(validSavedPage({items:[record()],next_cursor:''},principal,'alerts',filter,record().id)).toBe(false);expect(validSavedPage({items:[record()],next_cursor:''},principal,'alerts',{...filter,visibility:'team'},'')).toBe(false)
 })
 it('应用条件核对数据集、查询参数和纳秒窗口，不接收额外执行参数',()=>{
  const value=record(),resolved=resolution(value);expect(validSavedResolution(resolved,value,principal)).toBe(true)
  for(const bad of [null,{}, {...resolved,tenant_id:'other'},{...resolved,id:'other'},{...resolved,generation_id:'other'},{...resolved,revision:2},{...resolved,definition:{...definition(),parser_version:'future'}},{...resolved,query:{...resolved.query,source_ip:'foreign'}},{...resolved,query:{...resolved.query,page:2}},{...resolved,query:{...resolved.query,page_size:50}},{...resolved,query:{...resolved.query,end:stamp}},{...resolved,query:{...resolved.query,start:'invalid'}},{...resolved,query:{...resolved.query,script:'execute'}},{...resolved,query:{...resolved.query,start:'2026-08-01T00:00:00Z',end:stamp}}])expect(validSavedResolution(bad,value,principal)).toBe(false)
  const fixed=record('context');fixed.definition.window={mode:'absolute',start:'2026-10-02T08:00:00.123456789+08:00',end:'2026-10-03T08:00:00.123456789+08:00'};fixed.definition.terms={...emptyTerms(),flow_id:'18446744073709551615',sensor_registration_id:'reg_owned',source_generation_id:'gen_owned'};expect(validSavedResolution(resolution(fixed),fixed,principal)).toBe(true)
  const equal=structuredClone(fixed.definition);equal.window={mode:'absolute',start:'2026-10-02T00:00:00.123456789Z',end:'2026-10-03T00:00:00.123456789Z'};expect(sameDefinition(equal,fixed.definition)).toBe(true)
  const different=structuredClone(equal);different.window={mode:'absolute',start:'2026-10-02T00:00:00.123456788Z',end:'2026-10-03T00:00:00.123456789Z'};expect(sameDefinition(different,fixed.definition)).toBe(false)
  const invalid=structuredClone(equal);invalid.window={mode:'absolute',start:'invalid',end:stamp};expect(sameDefinition(invalid,invalid)).toBe(false)
  expect(sameDefinition({...definition(),mode:'advanced'},definition())).toBe(false);expect(sameDefinition({...definition(),window:{mode:'relative',hours:168}},definition())).toBe(false)
  expect(validSavedResolution({...resolution(fixed),query:{...resolution(fixed).query,start:'2026-10-02T00:00:00.123456788Z'}},fixed,principal)).toBe(false)
 })
})

describe('保存查询请求生命周期',()=>{
 it('按需读取有界目录，分页、筛选、损坏和迟到响应保持一致',async()=>{
  const {state,wrapper}=host(()=>useSavedSearches(()=> 'alerts'));expect(request).not.toHaveBeenCalled();await state.next();await state.previous();expect(request).not.toHaveBeenCalled()
  const items=Array.from({length:20},(_,i)=>record('alerts','sq_'+String(i).padStart(3,'0')))
  request.mockResolvedValueOnce({items,next_cursor:items.at(-1)!.id}).mockResolvedValueOnce({items:[record('alerts','sq_z')],next_cursor:''}).mockResolvedValueOnce({items,next_cursor:items.at(-1)!.id})
  await state.load();await state.next();expect(state.cursors.value).toEqual(['',items.at(-1)!.id]);await state.previous();expect(state.cursors.value).toEqual([''])
  request.mockResolvedValueOnce({items:[],next_cursor:''});await state.search({keyword:'  出口  ',visibility:'team',active:''});expect(request.mock.lastCall?.[0]).toContain('keyword=%E5%87%BA%E5%8F%A3');expect(state.filter.value.keyword).toBe('出口')
  request.mockResolvedValueOnce({items:[{}],next_cursor:''});await state.load();expect(state.error.value).toContain('未能完整返回');expect(state.page.value.items).toEqual([]);await state.next()
  request.mockRejectedValueOnce('offline');await state.load();expect(state.error.value).toContain('读取失败')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const loading=state.load(),signal=request.mock.lastCall![1].signal as AbortSignal;request.mockResolvedValue({items:[],next_cursor:''});user.value={...principal,id:'other'};await flushPromises();expect(signal.aborted).toBe(true);late.resolve({items:[record()],next_cursor:''});await loading;expect(state.page.value.items).toEqual([])
  wrapper.unmount();const count=request.mock.calls.length;await state.load();expect(request).toHaveBeenCalledTimes(count)
 })
 it('保存回执未知时锁定原输入并复用同一幂等键，明确拒绝可重新提交',async()=>{
  const {state}=host(()=>useSavedSearches(()=> 'alerts'));request.mockRejectedValueOnce(new Error('连接断开'));expect(await state.save(input())).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const first=request.mock.calls[0]![1];const clone=state.pendingInput()!;clone.name='改变草稿';expect(state.pendingInput()!.name).toBe(input().name);state.clearError();expect(state.mutationError.value).toBe('连接断开')
  expect(await state.save({...input(),name:'other'})).toBeUndefined();expect(request).toHaveBeenCalledTimes(1)
  request.mockResolvedValueOnce(record());expect(await state.confirm()).toMatchObject({id:'sq_owned'});expect(request.mock.calls[1]![1].headers).toEqual(first.headers);expect(request.mock.calls[1]![1].body).toEqual(first.body);expect(state.pendingInput()).toBeUndefined();expect(await state.confirm()).toBeUndefined()
  request.mockRejectedValueOnce(new ApiError(409,'saved_search_conflict','查询修订冲突'));await state.save(editSaved(record()));expect(state.unconfirmed.value).toBe(false);state.clearError();expect(state.mutationError.value).toBe('')
  request.mockResolvedValueOnce({...record(),name:'different'});await state.save(input());expect(state.unconfirmed.value).toBe(true);expect(state.mutationError.value).toContain('回执不完整')
 })
 it('只读账号可保存个人条件，禁止团队越权、异类数据集和非法变更',async()=>{
  const {state,wrapper}=host(()=>useSavedSearches(()=> 'alerts'));user.value={...principal,role:'viewer'};await flushPromises();expect(state.canEdit(record())).toBe(true);expect(state.canEdit({...record(),visibility:'team'})).toBe(false)
  await state.save({...input(),name:''});expect(state.mutationError.value).toContain('名称');await state.save(input('context'));expect(state.mutationError.value).toContain('数据集');await state.save({...input(),visibility:'team'});expect(state.mutationError.value).toContain('共享权限');expect(request).not.toHaveBeenCalled()
  request.mockResolvedValueOnce(record());expect(await state.save(input())).toMatchObject({visibility:'personal'})
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const saving=state.save(input());await state.save(input());expect(state.busy.value).toBe(true);expect(request).toHaveBeenCalledTimes(2);const signal=request.mock.lastCall![1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(record());expect(await saving).toBeUndefined();expect(await state.save(input())).toBeUndefined()
 })
 it('提交超时和 408 不误报成功；账号切换清除原提交与私有目录',async()=>{
  vi.useFakeTimers();const {state}=host(()=>useSavedSearches(()=> 'alerts'));request.mockImplementationOnce((_path,options)=>new Promise((_yes,no)=>options.signal.addEventListener('abort',()=>no(new Error('取消')))))
  const promise=state.save(input());await vi.advanceTimersByTimeAsync(30001);await promise;expect(state.unconfirmed.value).toBe(true);expect(state.mutationError.value).toContain('尚未确认')
  request.mockRejectedValueOnce(new ApiError(408,'request_timeout','超时'));await state.confirm();expect(state.unconfirmed.value).toBe(true)
  user.value={...principal,tenant_id:'other'};await flushPromises();expect(state.pendingInput()).toBeUndefined();expect(state.unconfirmed.value).toBe(false);expect(state.page.value.items).toEqual([])
 })
 it('解析只返回参数，过期修订、损坏结果和服务失败均阻止应用',async()=>{
  const {state,wrapper}=host(()=>useSavedSearches(()=> 'alerts'));for(const value of [{...record(),active:false},{...record(),definition:definition('context')},{...record(),definition:{...definition(),parser_version:'future'}}])expect(await state.resolve(value)).toBeUndefined();expect(request).not.toHaveBeenCalled()
  request.mockResolvedValueOnce(resolution());expect(await state.resolve(record())).toMatchObject({id:'sq_owned'});expect(request.mock.lastCall![1].body).toEqual({expected_revision:1,expected_generation_id:'querygen_owned',dataset:'alerts',parser_version:parserVersion})
  request.mockResolvedValueOnce({...resolution(),revision:2});expect(await state.resolve(record())).toBeUndefined();expect(state.error.value).toContain('不一致')
  request.mockRejectedValueOnce('offline');await state.resolve(record());expect(state.error.value).toContain('解析失败')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const resolving=state.resolve(record());expect(await state.resolve(record())).toBeUndefined();const signal=request.mock.lastCall![1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(resolution());expect(await resolving).toBeUndefined();expect(await state.resolve(record())).toBeUndefined()
 })
 it('目录切换取消旧请求，解析超时保留可理解错误',async()=>{
  const dataset=shallowRef<Dataset>('alerts'),{state}=host(()=>useSavedSearches(()=>dataset.value)),late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const loading=state.load(),signal=request.mock.lastCall![1].signal as AbortSignal;dataset.value='context';await flushPromises();expect(signal.aborted).toBe(true);late.resolve({items:[record()],next_cursor:''});await loading;expect(state.page.value.items).toEqual([])
  vi.useFakeTimers();request.mockImplementationOnce((_path,options)=>new Promise((_yes,no)=>options.signal.addEventListener('abort',()=>no(new Error('取消')))));const promise=state.resolve(record('context'));await vi.advanceTimersByTimeAsync(30001);await promise;expect(state.error.value).toContain('解析超时')
 })
})

describe('保存查询表单和条件复用',()=>{
 it('真实表单校验名称、聚焦错误并保持保存条件与当前列表分页独立',async()=>{
  const wrapper=form();await click('保存');expect(wrapper.emitted('save')).toBeUndefined();await flushPromises();expect(document.activeElement?.getAttribute('aria-label')).toBe('保存查询校验信息')
  await field('saved-query-name',' 办公请求 ');await field('saved-query-description',' 核对 HTTP ');await wrapper.findComponent(Select).setValue('team','value');await click('保存');expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({name:'办公请求',description:'核对 HTTP',visibility:'team',definition:definition()});await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
  await wrapper.setProps({error:'服务暂不可用'});await flushPromises();expect(document.activeElement?.getAttribute('aria-label')).toBe('保存查询校验信息');expect(document.body.textContent).toContain('团队共享仅共享查询定义')
 })
 it('编辑显式替换条件，未知结果锁定原输入并只允许核对原提交',async()=>{
  const current={...definition(),terms:{...emptyTerms(),path:'/current'}},wrapper=form({record:record(),current});await click('保存');expect(document.body.textContent).toContain('没有可提交');await wrapper.getComponent(Checkbox).setValue(true,'checked');await click('保存');const saved=wrapper.emitted('save')?.[0]?.[0] as SavedChange;expect(saved.definition.terms.path).toBe('/current');expect(saved.expected_generation_id).toBe('querygen_owned')
  await wrapper.setProps({unconfirmed:true,draft:saved,error:'回执未确认'});await flushPromises();expect((document.querySelector('#saved-query-name') as HTMLInputElement).disabled).toBe(true);expect(document.body.textContent).toContain('/current');await click('核对原提交');expect(wrapper.emitted('confirm')).toHaveLength(1)
  wrapper.unmount();const restored=form({draft:saved,unconfirmed:true,current:definition()});expect((document.querySelector('#saved-query-name') as HTMLInputElement).value).toBe(saved.name);expect(document.body.textContent).toContain('/current');await restored.setProps({busy:true});expect(button('核对原提交').disabled).toBe(true)
 })
 it('查询摘要区分全范围、固定时间、高级过滤和来源代次',async()=>{
  const wrapper=mount(QuerySummary,{props:{definition:definition()}});expect(wrapper.text()).toContain('所选时间范围内的全部记录');const context=definition('context');context.mode='advanced';context.window={mode:'absolute',start:'2026-10-02T00:00:00Z',end:stamp};context.terms={...emptyTerms(),filter:'tcp.port == 443',sensor_registration_id:'reg_owned',source_generation_id:'gen_owned',flow_id:'18446744073709551615'};await wrapper.setProps({definition:context});expect(wrapper.text()).toContain('协议记录');expect(wrapper.text()).toContain('固定时间范围');expect(wrapper.text()).toContain('18446744073709551615');expect(wrapper.text()).toContain('tcp.port == 443')
 })
 it('复用查询同步过滤表单，取消旧表达式校验并保留固定窗口',async()=>{
  request.mockResolvedValue({fields:[]});const wrapper=mount(TrafficFilters,{global,props:{pending:false},attachTo:document.body});await click('高级检索');await wrapper.get('textarea').setValue('tcp');const late=deferred<{valid:boolean}>();request.mockReturnValueOnce(late.promise);await wrapper.get('form').trigger('submit');await flushPromises();const signal=request.mock.lastCall![1].signal as AbortSignal
  const applied=definition('context');applied.window={mode:'absolute',start:'2026-10-02T00:00:00Z',end:stamp};applied.terms={...emptyTerms(),sensor_registration_id:'reg_owned',source_generation_id:'gen_owned',flow_id:'18446744073709551615',path:'/api'};await wrapper.setProps({applied,fixed:true});expect(signal.aborted).toBe(true);late.resolve({valid:true});await flushPromises();expect(wrapper.emitted('search')).toBeUndefined();expect(wrapper.get('input[aria-label="探针注册标识"]').element).toHaveProperty('value','reg_owned');expect(wrapper.get('input[aria-label="采集实例标识"]').element).toHaveProperty('value','gen_owned');expect(wrapper.text()).toContain('固定时间范围');await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('search')?.[0]?.[1]).toBe(0)
  wrapper.unmount();const alerts=mount(AlertFilters,{global,props:{pending:false},attachTo:document.body});const alertDef=definition();alertDef.terms.path='/from-saved';alertDef.window={mode:'absolute',start:'2026-10-02T00:00:00Z',end:stamp};await alerts.setProps({applied:alertDef,inherited:true});expect(alerts.text()).toContain('固定时间范围');await alerts.get('form').trigger('submit');await flushPromises();expect(alerts.emitted('search')?.[0]).toMatchObject([{path:'/from-saved'},0])
 })
 it('固定窗口刷新、翻页不移动时间；相对查询重算窗口并在账号切换后清空',async()=>{
  request.mockImplementation((_path,options)=>Promise.resolve({items:[],total:0,page:options.body.page,page_size:options.body.page_size}));const alerts=host(useAlerts),traffic=host(useTraffic);await flushPromises();const fixed=record('context');fixed.definition.window={mode:'absolute',start:'2026-10-02T00:00:00Z',end:stamp};const q=resolution(fixed).query as TrafficQuery;traffic.state.applyQuery(q,0);alerts.state.applyQuery({...q,filter:''} as SearchRequest,0);await flushPromises();traffic.state.refresh();alerts.state.refresh();await flushPromises();expect(traffic.state.definition.value.window).toEqual(fixed.definition.window);expect(alerts.state.definition.value.window).toEqual(fixed.definition.window);traffic.state.page(2,20);alerts.state.page(2,20);await flushPromises();expect(traffic.state.definition.value.window).toEqual(fixed.definition.window)
  traffic.state.search(defaultTrafficFilters(),0);alerts.state.search({...emptyTerms(),filter:''},0);await flushPromises();expect(traffic.state.fixed.value).toBe(true);expect(alerts.state.inherited.value).toBe(true)
  user.value={...principal,id:'other'};await flushPromises();expect(traffic.state.fixed.value).toBe(false);expect(alerts.state.inherited.value).toBe(false);expect(traffic.state.definition.value.window).toEqual({mode:'relative',hours:24});expect(alerts.state.definition.value.terms.path).toBe('');expect(traffic.state.result.value.items).toEqual([])
  traffic.state.applyQuery(q,168);alerts.state.applyQuery(q,168);await flushPromises();traffic.state.refresh();alerts.state.refresh();await flushPromises();expect(traffic.state.definition.value.window).toEqual({mode:'relative',hours:168});expect(alerts.state.definition.value.window).toEqual({mode:'relative',hours:168})
 })
})

describe('保存查询工作区交互',()=>{
 it('个人目录查看与应用使用独立弹窗，页面不增加第二张表',async()=>{
  const value=record();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/saved-searches?')?{items:[value],next_cursor:''}:resolution(value)))
  const wrapper=mount(SavedSearchTools,{global,props:{dataset:'alerts',current:definition(),disabled:false},attachTo:document.body});expect(request).not.toHaveBeenCalled();await click('已保存查询');expect(document.body.textContent).toContain('办公出口查询');expect(document.querySelectorAll('.ant-table')).toHaveLength(0);await click('查看');expect(document.body.textContent).toContain('核对请求行为');await click('返回列表');await click('应用');expect(wrapper.emitted('apply')?.[0]?.[0]).toMatchObject({id:value.id})
 })
 it('目录编辑固定修订与代次，重置和刷新保留分页含义，切换账号清除表单',async()=>{
  const value=record();request.mockImplementation((path:string,options?:{body?:SavedChange})=>Promise.resolve(path.startsWith('/saved-searches?')?{items:[value],next_cursor:''}:receipt(options!.body!)))
  const wrapper=mount(SavedSearchTools,{global,props:{dataset:'alerts',current:definition(),disabled:false},attachTo:document.body});await click('已保存查询');await click('编辑');await field('saved-query-name','已核对办公出口');await click('保存');expect(request.mock.calls.find(c=>c[0]==='/saved-searches')?.[1].body).toMatchObject({id:value.id,expected_revision:1,expected_generation_id:value.generation_id,name:'已核对办公出口'});await click('已保存查询');await click('重置');await click('刷新查询');expect(document.body.textContent).toContain('第 1 页');user.value={...principal,id:'other'};await flushPromises();expect(wrapper.findComponent(SaveQueryForm).exists()).toBe(false)
 })
 it('空目录、读取失败和重试具有独立状态',async()=>{
  request.mockResolvedValueOnce({items:[],next_cursor:''});mount(SavedSearchTools,{global,props:{dataset:'alerts',current:definition(),disabled:false},attachTo:document.body});await click('已保存查询');expect(document.body.textContent).toContain('没有保存查询');request.mockRejectedValueOnce(new Error('目录不可用'));await click('刷新查询');expect(document.body.textContent).toContain('目录不可用');request.mockResolvedValueOnce({items:[],next_cursor:''});await click('重试');expect(document.body.textContent).toContain('没有保存查询')
 })
 it('未知提交关闭后可恢复，只允许以原回执标识确认',async()=>{
  mount(SavedSearchTools,{global,props:{dataset:'alerts',current:definition(),disabled:false},attachTo:document.body});await click('保存当前查询');await field('saved-query-name','办公请求');request.mockRejectedValueOnce(new Error('未知回执'));await click('保存');expect(document.body.textContent).toContain('字段已锁定');const frozen=request.mock.calls.find(c=>c[0]==='/saved-searches')![1];await click('关闭');await click('核对原提交');request.mockImplementation((path:string,options?:{body?:SavedChange})=>Promise.resolve(path==='/saved-searches'?receipt(options!.body!):{items:[],next_cursor:''}));await click('核对原提交',document.querySelector('.ant-modal')!);expect(request.mock.calls.filter(c=>c[0]==='/saved-searches').at(-1)![1].headers).toEqual(frozen.headers)
 })
 it('停用及解析器版本不兼容的查询不能应用',async()=>{
  const inactive={...record(),active:false,expires_at:'2027-04-01T00:00:00Z'},future={...record('alerts','sq_future'),definition:{...definition(),parser_version:'future'}};request.mockResolvedValueOnce({items:[future,inactive],next_cursor:''});const wrapper=mount(SavedSearchTools,{global,props:{dataset:'alerts',current:definition(),disabled:false},attachTo:document.body});await click('已保存查询');await wrapper.findAllComponents(Select).at(-1)!.setValue('','value');request.mockResolvedValueOnce({items:[future,inactive],next_cursor:''});await click('筛选');await click('查看');expect(document.body.textContent).toContain('版本不兼容');expect(button('应用查询').disabled).toBe(true);await click('返回列表')
 })
 it('工具栏应用后驱动真实检索组件，并同步输入框和固定时间含义',async()=>{
  for(const dataset of ['alerts','context'] as const){
   const value=record(dataset);value.definition.window={mode:'absolute',start:'2026-10-02T00:00:00Z',end:stamp};value.definition.terms.path='/saved-path'
   request.mockImplementation((path:string,options?:{body?:SearchRequest})=>Promise.resolve(path.startsWith('/saved-searches?')?{items:[value],next_cursor:''}:path.endsWith('/resolve')?resolution(value):path.endsWith('/search')?{items:[],total:0,page:options!.body!.page,page_size:options!.body!.page_size}:{fields:[]}))
   const wrapper=mount(dataset==='alerts'?AlertsWorkspace:TrafficEvents,{global,attachTo:document.body});await flushPromises();await click('已保存查询');await click('应用');expect(request.mock.calls.filter(c=>c[0]===(dataset==='alerts'?'/alerts/search':'/traffic/search')).at(-1)![1].body).toMatchObject({path:'/saved-path',start:value.definition.window.start,end:value.definition.window.end,page:1,page_size:20});expect(wrapper.text()).toContain('固定时间范围');expect(wrapper.get(dataset==='alerts'?'input[id="alert-filters_path"]':'input[aria-label="HTTP 路径前缀"]').element).toHaveProperty('value','/saved-path');await click('刷新');expect(request.mock.lastCall![1].body.start).toBe(value.definition.window.start);wrapper.unmount();document.body.replaceChildren();request.mockClear()
  }
 })
})
