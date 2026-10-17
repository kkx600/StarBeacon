import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,shallowRef,type ShallowRef} from 'vue'
import {Select,Modal,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useIncidentTasks} from '../platform/src/features/incidents/useIncidentTasks'
import {newTaskSpec,taskSpecError,validTaskSpec,validTaskRecord,validTaskPage,validTaskHistory,sameTaskSpec,type IncidentTaskInput,type IncidentTaskRecord} from '../platform/src/features/incidents/incidentTask'
import type {IncidentRecord} from '../platform/src/features/incidents/incident'
import IncidentTaskForm from '../platform/src/features/incidents/IncidentTaskForm.vue'
import IncidentTasksModal from '../platform/src/features/incidents/IncidentTasksModal.vue'
import IncidentsWorkspace from '../platform/src/features/incidents/IncidentsWorkspace.vue'
import {incidentRecord,incidentClosed,incidentOwners,incidentPage} from './incidentFixtures'
import {incidentTaskCreate,incidentTask,incidentTaskDone,incidentTaskChange,incidentTaskPage} from './incidentTaskFixtures'
import {principal,deferred,click,button,closedMessage} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
vi.mock('vue-router',()=>({useRoute:()=>({query:{}}),useRouter:()=>({replace:vi.fn()})}))
const global={plugins:[registerAnt]},clone=<T,>(value:T):T=>structuredClone(value)
const root='/incidents/'+incidentRecord.id+'/tasks'
function answer(path:string,options?:{method?:string;body?:any}){
 return Promise.resolve(path==='/incidents/assignees'?incidentOwners:path.startsWith('/incidents?')?incidentPage:path.includes('/tasks')?(options?.method==='POST'?('expected_revision' in options.body?incidentTaskDone:incidentTask):path.includes('/history?')?{items:[incidentTaskDone,incidentTask],next_cursor:''}:path.includes('/tasks?')?incidentTaskPage:incidentTask):incidentRecord)
}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation(answer);vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(parent=shallowRef<IncidentRecord|null>(incidentRecord)){
 let state!:ReturnType<typeof useIncidentTasks>
 const wrapper=mount(defineComponent({setup(){state=useIncidentTasks(parent);return()=>h('div')}}))
 return{state,wrapper,parent}
}
async function form(props:Record<string,unknown>={}){
 const w=mount(IncidentTaskForm,{props:{parent:incidentRecord,record:null,editing:false,assignees:incidentOwners.items,ownerPending:false,ownerError:'',busy:false,unconfirmed:false,...props},global,attachTo:document.body});await flushPromises();return w
}
async function field(label:string,value:string){const el=document.querySelector<HTMLInputElement|HTMLTextAreaElement>(`[aria-label="${label}"]`)!;expect(el).not.toBeNull();el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
async function modal(parent:IncidentRecord=incidentRecord){const {state,wrapper}=host(shallowRef(parent));await flushPromises();const view=mount(IncidentTasksModal,{props:{parent,state,assignees:incidentOwners.items,ownerPending:false,ownerError:'',parentPending:false,parentError:''},global,attachTo:document.body});await flushPromises();return{state,wrapper,view}}

describe('协作任务材料与回执契约',()=>{
 it('校验标题、负责人、截止和终态材料，并拒绝控制字符及未知枚举',()=>{
  expect(taskSpecError(incidentTask.spec)).toBe('');expect(taskSpecError(newTaskSpec())).not.toBe('');expect(validTaskSpec(incidentTask.spec)).toBe(true)
  for(const spec of [{...incidentTask.spec,title:' '},{...incidentTask.spec,title:'字'.repeat(121)},{...incidentTask.spec,description:'\u0000'},{...incidentTask.spec,status:'toString'},{...incidentTask.spec,priority:'toString'},{...incidentTask.spec,assignee_id:'bad/id'},{...incidentTask.spec,due_at:'invalid'},{...incidentTask.spec,due_at:'2026-02-30T12:00:00Z'},{...incidentTask.spec,due_at:'2026-13-18T10:00:00Z'},{...incidentTask.spec,due_at:'1999-01-01T00:00:00Z'},{...incidentTask.spec,due_at:'2101-01-01T00:00:00Z'},{...incidentTask.spec,status:'in_progress',assignee_id:''},{...incidentTaskDone.spec,assignee_id:''},{...incidentTaskDone.spec,resolution:''},{...incidentTask.spec,resolution:'未清空旧依据'}])expect(taskSpecError(spec as any)).not.toBe('')
  expect(taskSpecError({...incidentTask.spec,description:'材料\n说明\t核对',due_at:null,assignee_id:''})).toBe('');expect(taskSpecError({...incidentTaskDone.spec,status:'cancelled',assignee_id:''})).toBe('')
  for(const spec of [null,[],{}, {...incidentTask.spec,unexpected:true},{...incidentTask.spec,resolution:null}])expect(validTaskSpec(spec)).toBe(false)
 })
 it('严格绑定事件、修订、操作人和时间，拒绝重复任务与跨任务历史',()=>{
  expect(validTaskRecord(incidentTask,incidentRecord.id)).toBe(true);expect(validTaskRecord({...incidentTask,spec:{...incidentTask.spec,assignee_id:''},assignee_name:''},incidentRecord.id)).toBe(true)
  const changes:Array<(v:any)=>void>=[v=>v.id='bad/id',v=>v.incident_id='case_foreign',v=>v.incident_revision=0,v=>v.revision=1001,v=>v.spec=null,v=>v.actor_id='',v=>v.actor_name='',v=>v.note='',v=>v.created_at='bad',v=>v.recorded_at='2025-01-01T00:00:00Z',v=>v.expires_at=v.recorded_at,v=>v.assignee_name='',v=>v.assignee_name=null,v=>{v.spec.assignee_id='';v.assignee_name='unexpected'}]
  for(const change of changes){const value=clone(incidentTask);change(value);expect(validTaskRecord(value,incidentRecord.id)).toBe(false)}
  expect(validTaskPage(incidentTaskPage,incidentRecord.id)).toBe(true)
  const rows=Array.from({length:20},(_,i)=>({...incidentTask,id:'case_task_'+i}))
  expect(validTaskPage({items:rows,next_cursor:rows[19]!.id},incidentRecord.id)).toBe(true)
  for(const page of [null,{}, {items:[incidentTask,incidentTask],next_cursor:''},{...incidentTaskPage,next_cursor:incidentTask.id},{items:[...rows,incidentTask],next_cursor:''},{items:[incidentTask,{...incidentTask,id:'later',created_at:'2026-10-18T02:00:00Z'}],next_cursor:''},{...incidentTaskPage,next_cursor:3}])expect(validTaskPage(page,incidentRecord.id)).toBe(false)
  const history={items:[incidentTaskDone,incidentTask],next_cursor:''};expect(validTaskHistory(history,incidentRecord.id,incidentTask.id)).toBe(true)
  for(const page of [null,{}, {...history,items:[incidentTask,incidentTaskDone]},{...history,items:[incidentTask,incidentTask]},{...history,next_cursor:'1'},{...history,next_cursor:0},{...history,items:[{...incidentTask,id:'other'}]}])expect(validTaskHistory(page,incidentRecord.id,incidentTask.id)).toBe(false)
  const revisions=Array.from({length:20},(_,i)=>({...incidentTask,revision:21-i}));expect(validTaskHistory({items:revisions,next_cursor:'2'},incidentRecord.id,incidentTask.id)).toBe(true)
 })
 it('比较纳秒精度和等价时区，拒绝毫秒以下的材料偏差',()=>{
  expect(sameTaskSpec(incidentTask.spec,clone(incidentTask.spec))).toBe(true)
  expect(sameTaskSpec(incidentTask.spec,{...incidentTask.spec,due_at:'2026-10-18T18:30:15.123456789+08:00'})).toBe(true)
  for(const due_at of [null,'invalid','2026-10-18T10:30:15.123456788Z'])expect(sameTaskSpec(incidentTask.spec,{...incidentTask.spec,due_at})).toBe(false)
  expect(sameTaskSpec(incidentTask.spec,{...incidentTask.spec,title:'其他任务'})).toBe(false)
 })
})

describe('协作任务请求生命周期',()=>{
 it('分页筛选、独立详情与历史读取遵循事件身份',async()=>{
  const {state}=host();await flushPromises();expect(request).toHaveBeenCalledWith(root+'?status=&before=',expect.objectContaining({signal:expect.any(AbortSignal)}));expect(state.page.value.items).toHaveLength(1)
  const rows=Array.from({length:20},(_,i)=>({...incidentTask,id:'case_task_'+i}));request.mockResolvedValueOnce({items:rows,next_cursor:rows[19]!.id});await state.refresh();state.next();await flushPromises();expect(state.cursors.value).toHaveLength(2);state.previous();await flushPromises();state.previous();expect(state.cursors.value).toHaveLength(1);state.search('completed');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('status=completed')
  await state.loadHistory();await state.select(incidentTask.id);await state.loadHistory();expect(state.history.value).toHaveLength(2);expect(state.historyLoaded.value).toBe(true)
  request.mockResolvedValueOnce({items:[incidentTask],next_cursor:''});await state.loadHistory('2');expect(state.history.value).toHaveLength(2)
  state.clearSelection();expect(state.selected.value).toBeNull();expect(state.historyLoaded.value).toBe(false)
 })
 it('拒绝残缺和跨事件内容，保留错误入口；旧列表和详情不能回填',async()=>{
  const {state,parent}=host();await flushPromises();request.mockResolvedValueOnce(null);await state.refresh();expect(state.error.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toContain('失败')
  request.mockResolvedValueOnce({...incidentTask,incident_id:'foreign'});await state.select(incidentTask.id);expect(state.selected.value).toBeNull();expect(state.detailError.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.select(incidentTask.id);expect(state.detailError.value).toContain('失败')
  await state.select(incidentTask.id);request.mockResolvedValueOnce({items:[incidentTaskDone],next_cursor:''});await state.loadHistory('2');expect(state.historyError.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.loadHistory();expect(state.historyError.value).toContain('失败')
  const list=deferred<unknown>();request.mockReturnValueOnce(list.promise);const reading=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;parent.value={...incidentRecord,id:'case_other'};await flushPromises();expect(signal.aborted).toBe(true);list.resolve(incidentTaskPage);await reading;expect(state.page.value.items).toHaveLength(0)
  parent.value=incidentRecord;await flushPromises();const detail=deferred<unknown>();request.mockReturnValueOnce(detail.promise);const readingDetail=state.select(incidentTask.id);state.clearSelection();detail.resolve(incidentTask);await readingDetail;expect(state.selected.value).toBeNull()
 })
 it('历史并发、身份切换和卸载取消旧读取，空事件不发出请求',async()=>{
  const {state,parent,wrapper}=host();await flushPromises();await state.select(incidentTask.id);const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const loading=state.loadHistory();const signal=request.mock.lastCall?.[1].signal as AbortSignal;state.clearSelection();late.resolve({items:[incidentTaskDone],next_cursor:''});await loading;expect(signal.aborted).toBe(true);expect(state.history.value).toEqual([])
  parent.value=null;await flushPromises();const count=request.mock.calls.length;await state.refresh();await state.select(incidentTask.id);await state.loadHistory();expect(request).toHaveBeenCalledTimes(count)
  parent.value=incidentRecord;await flushPromises();const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);const read=state.refresh();wrapper.unmount();pending.resolve(incidentTaskPage);await read;await state.refresh();expect(state.pending.value).toBe(true)
 })
 it('冻结未知提交与原键，确认不能改变任务、事件或材料',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));expect(await state.save('',incidentTaskCreate)).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];const frozen=state.pendingInput()!;frozen.input.spec.title='外部修改';expect(state.pendingInput()!.input.spec.title).toBe(incidentTask.spec.title)
  expect(await state.save('other',incidentTaskCreate)).toBeUndefined();expect(state.actionError.value).toContain('上次');state.clearActionError();expect(state.actionError.value).toContain('上次');expect(await state.confirm()).toEqual(incidentTask);expect(request.mock.calls.some(([,options])=>options?.headers?.['Idempotency-Key']===key)).toBe(true);await flushPromises();expect(state.unconfirmed.value).toBe(false);expect(state.pendingInput()).toBeUndefined();state.clearActionError();expect(state.actionError.value).toBe('');expect(await state.confirm()).toBeUndefined()
  expect(await state.save(incidentTask.id,incidentTaskChange)).toEqual(incidentTaskDone)
 })
 it('拒绝错误回执，确定拒绝解除冻结，超时回执仍需原请求确认',async()=>{
  const {state}=host();await flushPromises();request.mockResolvedValueOnce({...incidentTask,actor_id:'other'});await state.save('',incidentTaskCreate);expect(state.unconfirmed.value).toBe(true);await state.confirm();await flushPromises()
  request.mockRejectedValueOnce(new ApiError(409,'revision','请刷新修订'));await state.save(incidentTask.id,incidentTaskChange);expect(state.unconfirmed.value).toBe(false);expect(state.actionError.value).toContain('刷新')
  request.mockResolvedValueOnce({...incidentTaskDone,note:'其他说明'});await state.save(incidentTask.id,incidentTaskChange);expect(state.unconfirmed.value).toBe(true);await state.confirm();await flushPromises()
  request.mockRejectedValueOnce(new ApiError(408,'timeout','受理未知'));await state.save('',incidentTaskCreate);expect(state.unconfirmed.value).toBe(true);await state.confirm();await flushPromises()
  vi.useFakeTimers();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const writing=state.save('',incidentTaskCreate);await vi.advanceTimersByTimeAsync(30000);late.resolve(incidentTask);await writing;expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('尚未确认')
 })
 it('账号变化中止写入并清除冻结；重复点击和卸载不能接收晚到回执',async()=>{
  const {state,wrapper}=host();await flushPromises();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const saving=state.save('',incidentTaskCreate);expect(await state.save('',incidentTaskCreate)).toBeUndefined();const signal=request.mock.lastCall?.[1].signal as AbortSignal;(session.current as ShallowRef<Principal|null>).value={...principal,id:'other'};await flushPromises();expect(signal.aborted).toBe(true);late.resolve(incidentTask);await saving;expect(state.pendingInput()).toBeUndefined();expect(state.busy.value).toBe(false)
  const stopped=deferred<unknown>();request.mockReturnValueOnce(stopped.promise);const out=state.save('',incidentTaskCreate);wrapper.unmount();stopped.resolve(incidentTask);await out;expect(state.unconfirmed.value).toBe(false);expect(await state.save('',incidentTaskCreate)).toBeUndefined()
 })
})

describe('协作任务表单与单层弹窗',()=>{
 it('表单校验获得焦点，填写后创建，未修改的截止保留原纳秒精度',async()=>{
  const w=await form();w.vm.submit();await flushPromises();expect(document.activeElement?.getAttribute('aria-label')).toBe('任务表单校验信息');await field('任务标题','核对工作');await field('任务说明','检查原始材料。');w.vm.submit();expect(w.emitted('save')?.[0]?.[0]).toMatchObject({incident_revision:1,spec:{title:'核对工作',status:'open',due_at:null}});w.unmount()
  const editing=await form({record:incidentTask,editing:true});editing.vm.submit();await flushPromises();expect(document.body.textContent).toContain('本次变更说明');await field('任务变更说明','记录实际进展');editing.vm.submit();expect((editing.emitted('save')?.[0]?.[0] as IncidentTaskInput).spec.due_at).toBe(incidentTask.spec.due_at)
 })
 it('任务终态需要依据，重开清空旧依据，日期可清空或改成本地时间',async()=>{
  const w=await form({record:incidentTask,editing:true});const select=w.findAllComponents(Select)[0]!;await select.setValue('completed','value');await field('任务变更说明','核对完成');w.vm.submit();await flushPromises();expect(document.body.textContent).toContain('完成依据');await field('完成依据','检查已完成。');await field('任务截止时间','');w.vm.submit();expect((w.emitted('save')?.[0]?.[0] as IncidentTaskInput).spec).toMatchObject({status:'completed',resolution:'检查已完成。',due_at:null});await select.setValue('open','value');await field('任务截止时间','2026-10-19T08:30');w.vm.submit();const spec=(w.emitted('save')?.at(-1)?.[0] as IncidentTaskInput).spec;expect(spec.resolution).toBe('');expect(spec.due_at).toBe(new Date('2026-10-19T08:30').toISOString())
 })
 it('保留历史负责人和冻结修订，未知提交锁定表单，负责人失败可重试',async()=>{
  const historical={...incidentTask,assignee_name:'历史管理员'};const w=await form({record:historical,editing:true,assignees:[],ownerError:'目录无法读取'});expect(w.findAllComponents(Select)[2]!.props('options')).toContainEqual({value:principal.id,label:'历史管理员（历史负责人）',disabled:true});await click('重新读取负责人');expect(w.emitted('reloadOwners')).toHaveLength(1);await w.setProps({unconfirmed:true,draft:incidentTaskChange});w.vm.submit();expect(w.emitted('save')).toBeUndefined();expect(w.find('input[aria-label="任务标题"]').attributes('disabled')).toBeDefined()
  w.unmount();const frozen=await form({record:null,editing:true,draft:incidentTaskChange});frozen.vm.submit();expect(frozen.emitted('save')?.[0]?.[0]).toEqual(incidentTaskChange)
 })
 it('列表、详情、历史与编辑在同一弹窗切换，提交成功返回列表',async()=>{
  const {view}=await modal();expect(document.body.textContent).toContain(incidentTask.spec.title);await click('查看');expect(view.findComponent(Modal).exists()).toBe(true);await click('读取历史');expect(document.body.textContent).toContain('修订 2');await click('记录任务');await field('任务变更说明',incidentTaskChange.note);const status=view.findAllComponents(Select)[0]!;await status.setValue('completed','value');await field('完成依据',incidentTaskChange.spec.resolution);await click('保存任务');expect(request.mock.calls.some(([,options])=>options?.body?.expected_revision===1)).toBe(true);expect(document.querySelectorAll('.ant-modal-content')).toHaveLength(1);await click('建立任务');await field('任务标题',incidentTask.spec.title);await field('任务说明',incidentTask.spec.description);request.mockImplementationOnce((_path:string,options:any)=>({...incidentTask,spec:options.body.spec,assignee_name:options.body.spec.assignee_id?principal.username:''}));await click('保存任务');await click('关闭');expect(view.emitted('close')).toHaveLength(1)
 })
 it('空、失败、只读和未确认提交有明确入口，关闭弹窗后原键仍能确认',async()=>{
  request.mockImplementation((path:string,options:any)=>path.includes('/tasks?')?Promise.resolve({items:[],next_cursor:''}):answer(path,options));const {state,view}=await modal();expect(document.body.textContent).toContain('当前条件下没有');await click('刷新事件与任务');expect(view.emitted('reloadParent')).toHaveLength(1);await click('建立任务');await field('任务标题',incidentTask.spec.title);await field('任务说明',incidentTask.spec.description);request.mockRejectedValueOnce('network');await click('保存任务');expect(state.unconfirmed.value).toBe(true);expect(document.activeElement?.getAttribute('aria-label')).toBe('任务提交结果');await click('返回任务');await click('核对原提交');expect(view.findComponent(IncidentTaskForm).props('draft')).toBeDefined();const frozen=state.pendingInput()!;request.mockResolvedValueOnce({...incidentTask,spec:frozen.input.spec,assignee_name:frozen.input.spec.assignee_id?principal.username:''});await click('核对原提交',document.querySelector('.ant-modal-footer')!);expect(state.unconfirmed.value).toBe(false);view.unmount()
  const closed=await modal(incidentClosed);expect(button('建立任务').disabled).toBe(true);expect(document.body.textContent).toContain('事件已结案');closed.view.unmount()
 })

 it('未知任务提交关闭后可由工作区恢复，确认后重新读取事件修订',async()=>{
  let frozen:any,failed=false,parent=incidentRecord
  request.mockImplementation((path:string,options?:any)=>{
   if(path.includes('/tasks')&&options?.method==='POST'){if(!failed){failed=true;frozen=clone(options.body);return Promise.reject(new Error('结果未知'))}parent={...incidentRecord,revision:2};return Promise.resolve({...incidentTask,spec:frozen.spec,assignee_name:frozen.spec.assignee_id?principal.username:''})}
   if(path==='/incidents/'+incidentRecord.id)return Promise.resolve(parent)
   return answer(path,options)
  })
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');await click('协作任务');await click('建立任务');await field('任务标题',incidentTask.spec.title);await field('任务说明',incidentTask.spec.description);await click('保存任务');expect(w.findComponent(IncidentTaskForm).props('unconfirmed')).toBe(true);await click('关闭');await click('核对任务提交');expect(w.findComponent(IncidentTaskForm).props('draft')).toEqual(frozen);const key=request.mock.calls.find(([,options])=>options?.method==='POST')?.[1].headers['Idempotency-Key'];await click('核对原提交',document.querySelector('.ant-modal-footer')!);await flushPromises();expect(w.findComponent(IncidentTasksModal).props('parent').revision).toBe(2);expect(request.mock.calls.filter(([,options])=>options?.method==='POST').every(([,options])=>options.headers['Idempotency-Key']===key)).toBe(true)
 })
 it('工作区从事件详情进入任务时关闭详情，不同时叠加两份表单',async()=>{
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');await click('协作任务');expect(w.findComponent(IncidentTasksModal).exists()).toBe(true);expect(document.querySelectorAll('.ant-modal-content')).toHaveLength(1);await click('关闭');await click('建立事件');expect(document.querySelectorAll('.ant-modal-content')).toHaveLength(1)
 })
})
