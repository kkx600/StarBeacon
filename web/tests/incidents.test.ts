import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {Select,Modal,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useIncidents} from '../platform/src/features/incidents/useIncidents'
import {incidentSpecError,validIncidentRef,validIncidentRecord,validIncidentPage,validIncidentHistory,validIncidentAssignees,sameIncidentSpec,newIncidentSpec,type IncidentRecord} from '../platform/src/features/incidents/incident'
import IncidentForm from '../platform/src/features/incidents/IncidentForm.vue'
import IncidentDetail from '../platform/src/features/incidents/IncidentDetail.vue'
import IncidentsWorkspace from '../platform/src/features/incidents/IncidentsWorkspace.vue'
import {incidentRef,incidentInput,incidentRecord,incidentChange,incidentChanged,incidentClosed,incidentClosure,incidentOwners,incidentPage} from './incidentFixtures'
import {principal,deferred,click,button,closedMessage} from './fixtures'
const {request,replace,route}=vi.hoisted(()=>({request:vi.fn(),replace:vi.fn(),route:{query:{} as Record<string,string>}}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
vi.mock('vue-router',()=>({useRoute:()=>route,useRouter:()=>({replace})}))
const global={plugins:[registerAnt]},clone=<T,>(v:T):T=>structuredClone(v)
function answer(path:string,options?:{method?:string;body?:any}){return Promise.resolve(path==='/incidents/assignees'?incidentOwners:options?.method==='POST'?('expected_revision' in options.body?incidentChanged:incidentRecord):path.includes('/history?')?{items:[incidentChanged,incidentRecord],next_cursor:''}:path.startsWith('/incidents?')?incidentPage:incidentRecord)}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation(answer);route.query={};replace.mockReset();vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(){let state!:ReturnType<typeof useIncidents>;const wrapper=mount(defineComponent({setup(){state=useIncidents();return()=>h('div')}}));return{state,wrapper}}
const formProps={record:null,assignees:incidentOwners.items,assigneePending:false,assigneeError:'',busy:false,unconfirmed:false,error:''}
async function form(props:Record<string,unknown>={}){const w=mount(IncidentForm,{props:{...formProps,...props},global,attachTo:document.body});await flushPromises();return w}
async function input(id:string,value:string){const el=document.getElementById(id) as HTMLInputElement;el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('事件调查材料与身份契约',()=>{
 it('字段长度、枚举、控制字符和未结案材料遵循服务端约束',()=>{
  expect(incidentSpecError(incidentInput.spec)).toBe('');expect(incidentSpecError(newIncidentSpec())).not.toBe('')
  for(const spec of [{...incidentInput.spec,title:' 文'},{...incidentInput.spec,title:'文'.repeat(121)},{...incidentInput.spec,summary:'\u0000'},{...incidentInput.spec,category:'toString'},{...incidentInput.spec,severity:'toString'},{...incidentInput.spec,status:'pending'},{...incidentInput.spec,owner_id:'foreign/id'},{...incidentInput.spec,closure:incidentClosure}])expect(incidentSpecError(spec as any)).not.toBe('')
  expect(incidentSpecError({...incidentInput.spec,summary:'调查\n说明\t证据'})).toBe('')
  expect(validIncidentRef(incidentRef)).toBe(true);for(const ref of [null,[],{...incidentRef,event_id:''},{...incidentRef,event_id:'bad/id'},{...incidentRef,raw_sha256:'A'.repeat(64)}])expect(validIncidentRef(ref)).toBe(false)
 })
 it('结案要求责任人、四项材料和去重的复测引用，误报仍保存复核材料',()=>{
  expect(incidentSpecError(incidentClosed.spec)).toBe('')
  for(const spec of [{...incidentClosed.spec,owner_id:''},{...incidentClosed.spec,closure:null},{...incidentClosed.spec,closure:{...incidentClosure,reason:'other'}},{...incidentClosed.spec,closure:{...incidentClosure,impact:''}},{...incidentClosed.spec,closure:{...incidentClosure,evidence:[]}},{...incidentClosed.spec,closure:{...incidentClosure,evidence:['same','same']}},{...incidentClosed.spec,closure:{...incidentClosure,evidence:['x'.repeat(257)]}},{...incidentClosed.spec,closure:{...incidentClosure,evidence:null}}])expect(incidentSpecError(spec as any)).not.toBe('')
  expect(incidentSpecError({...incidentClosed.spec,closure:{...incidentClosure,reason:'false_positive',evidence:[]}})).toBe('')
  expect(sameIncidentSpec(incidentInput.spec,clone(incidentInput.spec))).toBe(true);expect(sameIncidentSpec(incidentClosed.spec,clone(incidentClosed.spec))).toBe(true);expect(sameIncidentSpec(incidentClosed.spec,incidentInput.spec)).toBe(false);expect(sameIncidentSpec(incidentClosed.spec,{...incidentClosed.spec,closure:{...incidentClosure,evidence:['changed']}})).toBe(false)
 })
 it('完整回执包含身份、来源和真实时间，列表与时间线拒绝跨事件及重复续点',()=>{
  expect(validIncidentRecord(incidentRecord)).toBe(true);expect(validIncidentPage(incidentPage)).toBe(true);expect(validIncidentHistory({items:[incidentChanged,incidentRecord],next_cursor:''},incidentRecord.id)).toBe(true);expect(validIncidentAssignees(incidentOwners)).toBe(true)
  const mutations:Array<(v:any)=>void>=[v=>v.id='bad/id',v=>v.revision=0,v=>v.revision=1001,v=>v.spec=null,v=>v.actor_id='',v=>v.actor_name='',v=>v.note='',v=>v.created_at='bad',v=>v.recorded_at='2025-01-01',v=>v.expires_at=v.recorded_at,v=>v.owner_name='',v=>v.alerts=null,v=>v.alerts.push(v.alerts[0]),v=>v.alerts[0].sensor_id='',v=>v.alerts[0].event_time='bad']
  for(const mutate of mutations){const r=clone(incidentRecord);mutate(r);expect(validIncidentRecord(r)).toBe(false)}
  expect(validIncidentRecord({...incidentRecord,spec:{...incidentRecord.spec,owner_id:''},owner_name:'unapproved'})).toBe(false);expect(validIncidentRecord({...incidentRecord,spec:{...incidentRecord.spec,owner_id:''},owner_name:'',alerts:[]})).toBe(true)
  for(const value of [null,{items:[incidentRecord,incidentRecord],next_cursor:''},{items:[],next_cursor:'wrong'},{items:[{...incidentRecord,id:'bad/id'}],next_cursor:''}])expect(validIncidentPage(value)).toBe(false)
  for(const value of [null,{items:[incidentRecord,incidentChanged],next_cursor:''},{items:[{...incidentRecord,id:'foreign'}],next_cursor:''},{items:[incidentRecord],next_cursor:'1'}])expect(validIncidentHistory(value,incidentRecord.id)).toBe(false)
  for(const value of [null,{items:[...incidentOwners.items,...incidentOwners.items]},{items:[{id:'bad/id',name:'foreign'}]},{items:[{id:'user_owned',name:''}]}])expect(validIncidentAssignees(value)).toBe(false)
  const many=Array.from({length:20},(_,i)=>({...incidentRecord,id:'incident_'+i}));expect(validIncidentPage({items:many,next_cursor:many[19]!.id})).toBe(true)
  const history=Array.from({length:20},(_,i)=>({...incidentRecord,revision:21-i}));expect(validIncidentHistory({items:history,next_cursor:'2'},incidentRecord.id)).toBe(true)
 })
})

describe('事件调查请求与并发边界',()=>{
 it('分页、筛选和代次保护保留最近请求，失败有真实恢复入口',async()=>{
  const {state}=host();await flushPromises();state.previous();state.next();expect(state.page.value.items).toHaveLength(1)
  const rows=Array.from({length:20},(_,i)=>({...incidentRecord,id:'incident_'+i}));request.mockResolvedValueOnce({items:rows,next_cursor:rows[19]!.id});await state.refresh();state.next();await flushPromises();expect(state.cursors.value).toHaveLength(2);expect(request.mock.lastCall?.[0]).toContain('before=incident_19');state.previous();await flushPromises();expect(state.cursors.value).toEqual([''])
  state.search('investigating','high');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('status=investigating&severity=high')
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const pending=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;await state.refresh();expect(signal.aborted).toBe(true);old.resolve({items:[],next_cursor:''});await pending;expect(state.page.value.items).toHaveLength(1)
  request.mockResolvedValueOnce({items:[],next_cursor:'wrong'});await state.refresh();expect(state.error.value).toContain('完整返回');request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('事件列表读取失败');await state.refresh();expect(state.error.value).toBe('')
 })
 it('详情、历史和责任人校验身份，取消与卸载拒绝迟到的状态',async()=>{
  const {state,wrapper}=host();await flushPromises();await state.loadHistory();await state.reloadDetail();await state.select(incidentRecord.id);await state.loadHistory();expect(state.history.value).toHaveLength(2)
  request.mockResolvedValueOnce({items:[incidentChanged],next_cursor:''});await state.loadHistory('2');expect(state.historyError.value).toContain('完整返回');request.mockResolvedValueOnce({items:[incidentRecord],next_cursor:''});await state.loadHistory('2');expect(state.history.value).toHaveLength(2)
  request.mockRejectedValueOnce('offline');await state.loadHistory();expect(state.historyError.value).toBe('调查时间线读取失败');await state.loadHistory();expect(state.historyError.value).toBe('')
  request.mockResolvedValueOnce({...incidentRecord,id:'foreign'});await state.reloadDetail();expect(state.detailError.value).toContain('完整返回');request.mockRejectedValueOnce('offline');await state.reloadDetail();expect(state.detailError.value).toBe('事件详情读取失败');await state.reloadDetail()
  request.mockResolvedValueOnce({items:[{id:'foreign',name:''}]});await state.loadAssignees();expect(state.assigneeError.value).toContain('完整返回');request.mockRejectedValueOnce('offline');await state.loadAssignees();expect(state.assigneeError.value).toBe('责任人列表读取失败');await state.loadAssignees();expect(state.assignees.value).toEqual(incidentOwners.items)
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const read=state.select(incidentRecord.id);state.clearSelection();late.resolve(incidentRecord);await read;expect(state.selected.value).toBeNull()
  const disposed=deferred<unknown>();request.mockReturnValueOnce(disposed.promise);const requestRead=state.loadAssignees();wrapper.unmount();disposed.resolve(incidentOwners);await requestRead;await state.refresh();await state.select(incidentRecord.id);await state.loadHistory();await state.loadAssignees();expect(await state.save('',incidentInput)).toBeUndefined()
 })
 it('未知结果冻结输入和键，确认回执必须匹配修订、来源、用户和材料',async()=>{
  const {state}=host();await flushPromises();expect(await state.confirm()).toBeUndefined();request.mockRejectedValueOnce(new Error('连接中断'));await state.save('',incidentInput);expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers
  const pending=state.pendingInput()!;pending.input.spec.title='外部变更';expect(state.pendingInput()!.input.spec.title).toBe(incidentInput.spec.title);await state.save('',{...incidentInput,spec:{...incidentInput.spec,title:'changed'}});expect(state.actionError.value).toContain('核对原提交');state.clearActionError();expect(state.actionError.value).not.toBe('')
  expect(await state.confirm()).toEqual(incidentRecord);expect(request.mock.calls.filter(c=>c[1]?.method==='POST').map(c=>c[1].headers)).toEqual([key,key]);expect(state.unconfirmed.value).toBe(false);await flushPromises()
  for(const record of [{...incidentChanged,id:'foreign'},{...incidentChanged,revision:3},{...incidentChanged,actor_id:'foreign'},{...incidentChanged,spec:incidentInput.spec}]){request.mockResolvedValueOnce(record);await state.save(incidentRecord.id,incidentChange);expect(state.unconfirmed.value).toBe(true)}
  request.mockResolvedValueOnce(incidentChanged);expect(await state.confirm()).toEqual(incidentChanged);await flushPromises();request.mockResolvedValueOnce({...incidentRecord,alerts:[]});await state.save('',incidentInput);expect(state.unconfirmed.value).toBe(true)
 })
 it('确定拒绝释放输入，重复升级指向同租户既有调查',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new ApiError(409,'alert_already_linked','告警已关联事件','',{related_incident_id:incidentRecord.id}));await state.save('',incidentInput);expect(state.unconfirmed.value).toBe(false);expect(state.linkedID.value).toBe(incidentRecord.id);state.clearActionError();expect(state.linkedID.value).toBe('')
  request.mockRejectedValueOnce(new ApiError(429,'quota','今日额度已用尽'));await state.save('',incidentInput);expect(state.unconfirmed.value).toBe(false);expect(state.actionError.value).toContain('额度');expect(await state.confirm()).toBeUndefined()
  request.mockRejectedValueOnce(new ApiError(408,'timeout','结果未知'));await state.save('',incidentInput);expect(state.unconfirmed.value).toBe(true)
 })
 it('租户切换和卸载取消旧写入，重复提交不能重入',async()=>{
  const {state,wrapper}=host();await flushPromises();const late=deferred<IncidentRecord>();request.mockReturnValueOnce(late.promise);const writing=state.save('',incidentInput);expect(await state.save('',incidentInput)).toBeUndefined();const signal=request.mock.lastCall?.[1].signal as AbortSignal;(session.current as ShallowRef<Principal|null>).value={...principal,tenant_id:'tenant_other'};await flushPromises();expect(signal.aborted).toBe(true);late.resolve(incidentRecord);await writing;expect(state.selected.value).toBeNull();expect(state.pendingInput()).toBeUndefined()
  const stopped=deferred<IncidentRecord>();request.mockReturnValueOnce(stopped.promise);const out=state.save('',incidentInput);wrapper.unmount();stopped.resolve(incidentRecord);await out;expect(state.selected.value).toBeNull();await state.confirm()
 })
 it('写入超时保留原请求，不把晚到的成功当成已确认',async()=>{
  vi.useFakeTimers();const {state}=host();await flushPromises();const late=deferred<IncidentRecord>();request.mockReturnValueOnce(late.promise);const writing=state.save('',incidentInput);await vi.advanceTimersByTimeAsync(30000);late.resolve(incidentRecord);await writing;expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('尚未确认');expect(state.selected.value).toBeNull();await state.confirm();await flushPromises();expect(state.unconfirmed.value).toBe(false)
 })
})

describe('事件调查表单与材料交互',()=>{
 it('Escape 优先关闭当前下拉菜单，保留正在填写的调查表单',async()=>{
  const w=await form({record:incidentChanged});await input('incident-note','保留未提交的复核说明');
  const status=w.findAllComponents(Select)[2]!;await status.find('.ant-select-selector').trigger('mousedown');await flushPromises();
  const escape=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(escape,'which',{value:27});status.find('input').element.dispatchEvent(escape);await flushPromises();
  expect(w.emitted('close')).toBeUndefined();expect((document.getElementById('incident-note') as HTMLTextAreaElement).value).toBe('保留未提交的复核说明');
  expect(status.find('input').attributes('aria-expanded')).toBe('false');
  await input('incident-note','继续填写调查说明');await click('提交调查');expect(w.emitted('save')).toHaveLength(1);
 })
 it('长结案表单的校验与服务错误获得焦点，重复拒绝仍能定位到原因',async()=>{
  const w=await form({record:incidentChanged});const status=w.findAllComponents(Select)[2]!;await status.setValue('closed','value');status.vm.$emit('change','closed');await flushPromises();await input('incident-note','核对结案材料');await click('提交调查');const panel=document.querySelector('[aria-label="调查表单校验信息"]')!;expect(document.activeElement).toBe(panel);expect(panel.textContent).toContain('根因');await input('incident-summary','保持材料待核对');await click('提交调查');expect(document.activeElement).toBe(panel);w.unmount()
  const server=await form();await server.setProps({error:'提交结果尚未确认，请核对原请求'});await flushPromises();expect(document.activeElement?.textContent).toContain('提交结果尚未确认');expect(server.emitted('save')).toBeUndefined()
 })
 it('空值、残缺来源和未填调查说明保留表单，合法手工线索可以提交',async()=>{
  const w=await form();await click('建立事件');expect(w.emitted('save')).toBeUndefined();await input('incident-title','人工线索');await input('incident-summary','核对人工调查材料。');await input('incident-event',incidentRef.event_id);await click('建立事件');expect(document.body.textContent).toContain('同时提供');await input('incident-event','');await click('建立事件');expect(w.emitted('save')?.[0]?.[0]).toEqual({spec:{...newIncidentSpec(),title:'人工线索',summary:'核对人工调查材料。'},alerts:[]});await click('关闭');expect(w.emitted('close')).toHaveLength(1)
  w.unmount();const editing=await form({record:incidentRecord});await click('提交调查');expect(document.body.textContent).toContain('本次调查说明');await input('incident-note','核对实际来源');await input('incident-event',incidentRef.event_id);await input('incident-sha',incidentRef.raw_sha256);await click('提交调查');expect(document.body.textContent).toContain('当前事件');await input('incident-event','');await input('incident-sha','');await click('提交调查');expect(editing.emitted('save')?.[0]?.[0]).toEqual({...incidentChange,spec:incidentInput.spec,note:'核对实际来源'})
 })
 it('结案和重开切换材料，未知结果锁定字段但允许核对原提交',async()=>{
  const w=await form({record:incidentChanged});const status=w.findAllComponents(Select)[2]!;await status.setValue('closed','value');status.vm.$emit('change','closed');await flushPromises();await input('incident-note','结案核对');await click('提交调查');expect(document.body.textContent).toContain('根因');for(const [id,value] of [['incident-root',incidentClosure.root_cause],['incident-impact',incidentClosure.impact],['incident-remediation',incidentClosure.remediation],['incident-verification',incidentClosure.verification],['incident-evidence','owned:replay-result']])await input(id!,value!);await click('提交调查');expect((w.emitted('save')?.[0]?.[0] as any).spec.closure).toEqual(incidentClosure);await status.setValue('investigating','value');status.vm.$emit('change','investigating');await flushPromises();expect(document.getElementById('incident-root')).toBeNull()
  await w.setProps({unconfirmed:true,draft:incidentChange});expect((document.getElementById('incident-title') as HTMLInputElement).disabled).toBe(true);expect(button('核对原提交').disabled).toBe(false);await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);await w.setProps({busy:true});expect(w.getComponent(Modal).props('closable')).toBe(false)
 })
 it('责任人读取失败可恢复，重复告警可查看既有事件，响应式表单只展示一个操作区',async()=>{
  const w=await form({draft:incidentInput,seed:incidentRef,assigneeError:'责任人服务不可用',linkedId:incidentRecord.id});expect(button('建立事件').disabled).toBe(true);await click('重试责任人');expect(w.emitted('reloadOwners')).toHaveLength(1);await click('查看既有调查');expect(w.emitted('existing')).toEqual([[incidentRecord.id]]);expect(w.findAll('.ant-table')).toHaveLength(0)
 })
 it('详情展示冻结来源和时间线，历史结案可核对而不覆盖当前状态',async()=>{
  const w=mount(IncidentDetail,{props:{record:incidentClosed,pending:false,error:'',history:[incidentClosed,incidentChanged,incidentRecord],historyPending:false,historyError:'',next:'1'},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain(incidentRef.raw_sha256);expect(document.body.textContent).toContain('根因说明');await click('重开或复核');expect(w.emitted('edit')).toHaveLength(1);await click('调查时间线');expect(w.emitted('history')).toEqual([[]]);await click('读取更早记录');expect(w.emitted('history')).toEqual([[],['1']]);expect(document.body.textContent).toContain('修订 3');expect(w.findAll('.ant-table')).toHaveLength(0);await w.setProps({record:null,error:'事件读取失败'});await click('重试');expect(w.emitted('reload')).toHaveLength(1)
 })
 it('单列表页面通过弹窗建立、查看和修改，提交后保留实际修订',async()=>{
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();expect(w.findAll('.ant-table')).toHaveLength(1);await click('建立事件');await input('incident-title',incidentInput.spec.title);await input('incident-summary',incidentInput.spec.summary);await w.findAllComponents(Select).at(-1)!.setValue(principal.id,'value');await click('建立事件',document.querySelector('.ant-modal-content')!);expect(message.success).toHaveBeenCalledWith('事件已建立');expect(document.body.textContent).toContain('调查概览');await click('记录调查');const status=w.findAllComponents(Select).at(-2)!;await status.setValue('investigating','value');status.vm.$emit('change','investigating');await input('incident-note',incidentChange.note);await click('提交调查');expect(message.success).toHaveBeenCalledWith('调查记录已提交');expect(w.findAll('.ant-table')).toHaveLength(1)
 })
 it('从告警携带真实摘要建立调查，未知结果可关闭后按原键恢复',async()=>{
  route.query={alert_id:incidentRef.event_id,sha256:incidentRef.raw_sha256};const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();expect((document.getElementById('incident-sha') as HTMLInputElement).value).toBe(incidentRef.raw_sha256);await input('incident-title',incidentInput.spec.title);await input('incident-summary',incidentInput.spec.summary);await w.findAllComponents(Select).at(-1)!.setValue(principal.id,'value');request.mockRejectedValueOnce(new Error('响应连接中断'));await click('建立事件',document.querySelector('.ant-modal-content')!);await click('关闭');await click('核对原提交');expect((document.getElementById('incident-title') as HTMLInputElement).disabled).toBe(true);await click('核对原提交',document.querySelector('.ant-modal-content')!);expect(message.success).toHaveBeenCalledWith('事件已确认');expect(replace).toHaveBeenCalledWith({path:'/incidents'})
 })
})
