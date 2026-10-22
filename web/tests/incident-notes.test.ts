import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,shallowRef,type ShallowRef} from 'vue'
import {Select,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useIncidentNotes} from '../platform/src/features/incidents/useIncidentNotes'
import {newNoteSpec,noteSpecError,validNoteSpec,validNoteRecord,validNotePage,validNoteHistory,sameNoteSpec} from '../platform/src/features/incidents/incidentNote'
import type {IncidentRecord} from '../platform/src/features/incidents/incident'
import IncidentNoteForm from '../platform/src/features/incidents/IncidentNoteForm.vue'
import IncidentNotesModal from '../platform/src/features/incidents/IncidentNotesModal.vue'
import IncidentsWorkspace from '../platform/src/features/incidents/IncidentsWorkspace.vue'
import {incidentRecord,incidentClosed,incidentOwners,incidentPage} from './incidentFixtures'
import {incidentNoteCreate,incidentNote,incidentNoteWithdrawn,incidentNoteChange,incidentNotePage} from './incidentNoteFixtures'
import {principal,deferred,click,button,closedMessage} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
vi.mock('vue-router',()=>({useRoute:()=>({query:{}}),useRouter:()=>({replace:vi.fn()})}))
const global={plugins:[registerAnt]},clone=<T,>(value:T):T=>structuredClone(value)
const root='/incidents/'+incidentRecord.id+'/notes'
function answer(path:string,options?:{method?:string;body?:any}){
 return Promise.resolve(path==='/incidents/assignees'?incidentOwners:path.startsWith('/incidents?')?incidentPage:path.includes('/notes')?(options?.method==='POST'?('expected_revision' in options.body?incidentNoteWithdrawn:incidentNote):path.includes('/history?')?{items:[incidentNoteWithdrawn,incidentNote],next_cursor:''}:path.includes('/notes?')?incidentNotePage:incidentNote):incidentRecord)
}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation(answer);vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(parent=shallowRef<IncidentRecord|null>(incidentRecord)){
 let state!:ReturnType<typeof useIncidentNotes>;const wrapper=mount(defineComponent({setup(){state=useIncidentNotes(parent);return()=>h('div')}}));return{state,wrapper,parent}
}
async function form(props:Record<string,unknown>={}){const w=mount(IncidentNoteForm,{props:{parent:incidentRecord,record:null,editing:false,busy:false,unconfirmed:false,...props},global,attachTo:document.body});await flushPromises();return w}
async function field(label:string,value:string){const e=document.querySelector<HTMLInputElement|HTMLTextAreaElement>(`[aria-label="${label}"]`)!;expect(e).not.toBeNull();e.value=value;e.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
async function modal(parent:IncidentRecord=incidentRecord){const {state,wrapper}=host(shallowRef(parent));await flushPromises();const view=mount(IncidentNotesModal,{props:{parent,state,parentPending:false,parentError:''},global,attachTo:document.body});await flushPromises();return{state,wrapper,view}}

describe('调查笔记材料与固定作者契约',()=>{
 it('校验纯文本、状态与撤回原因，拒绝未知字段、控制字符和超长输入',()=>{
  expect(noteSpecError(incidentNote.spec)).toBe('');expect(noteSpecError(newNoteSpec())).not.toBe('');expect(validNoteSpec(incidentNote.spec)).toBe(true)
  for(const spec of [{...incidentNote.spec,title:' '},{...incidentNote.spec,title:'中'.repeat(121)},{...incidentNote.spec,body:''},{...incidentNote.spec,body:'中'.repeat(8193)},{...incidentNote.spec,body:'\r'},{...incidentNote.spec,status:'toString'},{...incidentNote.spec,withdrawal_reason:'旧原因'},{...incidentNoteChange.spec,withdrawal_reason:''},{...incidentNoteChange.spec,withdrawal_reason:'中'.repeat(2049)}])expect(noteSpecError(spec as any)).not.toBe('')
  for(const spec of [null,[],{}, {...incidentNote.spec,author_id:'other'}, {...incidentNote.spec,body:null}])expect(validNoteSpec(spec)).toBe(false)
  expect(noteSpecError({...incidentNote.spec,body:'材料\n说明\t核对'})).toBe('');expect(noteSpecError(incidentNoteWithdrawn.spec)).toBe('');expect(sameNoteSpec(incidentNote.spec,clone(incidentNote.spec))).toBe(true);expect(sameNoteSpec(incidentNote.spec,incidentNoteWithdrawn.spec)).toBe(false)
 })
 it('回执绑定事件、作者、操作人和纳秒时序，拒绝非法日期及重复列表',()=>{
  expect(validNoteRecord(incidentNote,incidentRecord.id)).toBe(true)
  const changes:Array<(v:any)=>void>=[v=>v.id='bad/id',v=>v.incident_id='case_other',v=>v.incident_revision=0,v=>v.revision=1001,v=>v.spec=null,v=>v.author_id='',v=>v.author_name='',v=>v.actor_id='other',v=>v.actor_name='',v=>v.reason='',v=>v.created_at='bad',v=>v.created_at='2026-02-30T00:00:00Z',v=>v.recorded_at='2026-10-01T00:02:00Z',v=>v.expires_at=v.recorded_at]
  for(const change of changes){const value=clone(incidentNote);change(value);expect(validNoteRecord(value,incidentRecord.id)).toBe(false)}
  expect(validNotePage(incidentNotePage,incidentRecord.id)).toBe(true)
  const rows=Array.from({length:20},(_,i)=>({...incidentNote,id:'case_note_'+i}));expect(validNotePage({items:rows,next_cursor:rows[19]!.id},incidentRecord.id)).toBe(true)
  for(const page of [null,{}, {items:[incidentNote,incidentNote],next_cursor:''},{...incidentNotePage,next_cursor:incidentNote.id},{items:[...rows,incidentNote],next_cursor:''},{items:[incidentNote,{...incidentNote,id:'later',created_at:'2026-10-01T00:02:00.000000002Z',recorded_at:'2026-10-01T00:02:00.000000002Z'}],next_cursor:''},{...incidentNotePage,next_cursor:1}])expect(validNotePage(page,incidentRecord.id)).toBe(false)
 })
 it('历史按修订降序绑定同一笔记，完整页提供精确续点',()=>{
  const history={items:[incidentNoteWithdrawn,incidentNote],next_cursor:''};expect(validNoteHistory(history,incidentRecord.id,incidentNote.id)).toBe(true)
  for(const p of [null,{}, {...history,items:[incidentNote,incidentNoteWithdrawn]},{...history,items:[incidentNote,incidentNote]},{...history,next_cursor:'1'},{...history,next_cursor:1},{...history,items:[{...incidentNote,id:'other'}]}])expect(validNoteHistory(p,incidentRecord.id,incidentNote.id)).toBe(false)
  const rows=Array.from({length:20},(_,i)=>({...incidentNote,revision:21-i}));expect(validNoteHistory({items:rows,next_cursor:'2'},incidentRecord.id,incidentNote.id)).toBe(true)
 })
})

describe('调查笔记异步读取与原提交确认',()=>{
 it('查询筛选、分页、独立详情和历史，不叠加业务列表',async()=>{
  const {state}=host();await flushPromises();expect(request).toHaveBeenCalledWith(root+'?status=&before=',expect.objectContaining({signal:expect.any(AbortSignal)}))
  const rows=Array.from({length:20},(_,i)=>({...incidentNote,id:'case_note_'+i}));request.mockResolvedValueOnce({items:rows,next_cursor:rows[19]!.id});await state.refresh();state.next();await flushPromises();expect(state.cursors.value).toHaveLength(2);state.previous();await flushPromises();state.previous();expect(state.cursors.value).toHaveLength(1)
  state.search('withdrawn');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('status=withdrawn');await state.loadHistory();await state.select(incidentNote.id);await state.loadHistory();expect(state.history.value).toHaveLength(2);request.mockResolvedValueOnce({items:[incidentNote],next_cursor:''});await state.loadHistory('2');expect(state.history.value).toHaveLength(2);state.clearSelection();expect(state.historyLoaded.value).toBe(false)
 })
 it('不完整、跨事件或失序结果不被显示，保留重新读取入口',async()=>{
  const {state}=host();await flushPromises();request.mockResolvedValueOnce(null);await state.refresh();expect(state.error.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toContain('失败')
  request.mockResolvedValueOnce({...incidentNote,incident_id:'other'});await state.select(incidentNote.id);expect(state.detailError.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.select(incidentNote.id);expect(state.detailError.value).toContain('失败')
  await state.select(incidentNote.id);request.mockResolvedValueOnce({items:[incidentNoteWithdrawn],next_cursor:''});await state.loadHistory('2');expect(state.historyError.value).toContain('完整');request.mockRejectedValueOnce('offline');await state.loadHistory();expect(state.historyError.value).toContain('失败');request.mockResolvedValueOnce({items:[{...incidentNote,author_id:'other',actor_id:'other'}],next_cursor:''});await state.loadHistory();expect(state.historyError.value).toContain('完整')
 })
 it('事件切换、关闭详情和卸载会取消旧读取，迟到内容不回填',async()=>{
  const {state,parent,wrapper}=host();await flushPromises();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const loading=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;parent.value={...incidentRecord,id:'case_other'};await flushPromises();expect(signal.aborted).toBe(true);late.resolve(incidentNotePage);await loading;expect(state.page.value.items).toHaveLength(0)
  parent.value=incidentRecord;await flushPromises();const detail=deferred<unknown>();request.mockReturnValueOnce(detail.promise);const reading=state.select(incidentNote.id);state.clearSelection();detail.resolve(incidentNote);await reading;expect(state.selected.value).toBeNull()
  await state.select(incidentNote.id);const hist=deferred<unknown>();request.mockReturnValueOnce(hist.promise);const readingHistory=state.loadHistory();state.clearSelection();hist.resolve({items:[incidentNote],next_cursor:''});await readingHistory;expect(state.history.value).toEqual([])
  parent.value=null;await flushPromises();const count=request.mock.calls.length;await state.refresh();await state.select(incidentNote.id);await state.loadHistory();expect(request).toHaveBeenCalledTimes(count);wrapper.unmount();await state.refresh()
 })
 it('关闭同时失效列表和历史，暂停后不发起读取，详情迟到也不回填',async()=>{
  const {state}=host();await flushPromises();await state.select(incidentNote.id)
  const history=deferred<unknown>();request.mockReturnValueOnce(history.promise);const readingHistory=state.loadHistory(),historySignal=request.mock.lastCall?.[1].signal as AbortSignal
  const list=deferred<unknown>();request.mockReturnValueOnce(list.promise);const readingList=state.refresh(),listSignal=request.mock.lastCall?.[1].signal as AbortSignal
  state.close();expect(historySignal.aborted).toBe(true);expect(listSignal.aborted).toBe(true)
  history.resolve({items:[incidentNoteWithdrawn,incidentNote],next_cursor:''});list.resolve(incidentNotePage);await Promise.all([readingHistory,readingList])
  expect(state.page.value.items).toEqual([]);expect(state.history.value).toEqual([]);expect(state.historyPending.value).toBe(false);expect(state.pending.value).toBe(false)
  const count=request.mock.calls.length;await state.refresh();await state.select(incidentNote.id);await state.loadHistory();expect(request).toHaveBeenCalledTimes(count)
  state.open();await flushPromises();expect(state.page.value.items).toEqual([incidentNote])
  const detail=deferred<unknown>();request.mockReturnValueOnce(detail.promise);const readingDetail=state.select(incidentNote.id),detailSignal=request.mock.lastCall?.[1].signal as AbortSignal
  state.close();expect(detailSignal.aborted).toBe(true);detail.resolve(incidentNote);await readingDetail;expect(state.selected.value).toBeNull();expect(state.detailPending.value).toBe(false)
 })
 it('关闭和重开读取不清除未知提交，确认仍使用原键与原材料',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));await state.save('',incidentNoteCreate)
  const original=state.pendingInput(),key=request.mock.lastCall?.[1].headers['Idempotency-Key'];expect(state.unconfirmed.value).toBe(true)
  state.close();expect(state.pendingInput()).toEqual(original);expect(state.unconfirmed.value).toBe(true)
  state.open();await flushPromises();expect(state.pendingInput()).toEqual(original);expect(await state.confirm()).toEqual(incidentNote)
  const submissions=request.mock.calls.filter(([,options])=>options?.method==='POST');expect(submissions).toHaveLength(2)
  expect(submissions.every(([,options])=>options.headers['Idempotency-Key']===key&&JSON.stringify(options.body)===JSON.stringify(original?.input))).toBe(true)
  expect(state.unconfirmed.value).toBe(false);expect(state.pendingInput()).toBeUndefined()
 })
 it('网络中断冻结原键和输入，核对不会变更作者、事件或材料',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));expect(await state.save('',incidentNoteCreate)).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];const original=state.pendingInput()!;original.input.spec.title='篡改';expect(state.pendingInput()!.input.spec.title).toBe(incidentNote.spec.title)
  expect(await state.save('other',incidentNoteCreate)).toBeUndefined();state.clearActionError();expect(state.actionError.value).toContain('上次');expect(await state.confirm()).toEqual(incidentNote);expect(request.mock.calls.some(([,o])=>o?.headers?.['Idempotency-Key']===key)).toBe(true);await flushPromises();expect(state.unconfirmed.value).toBe(false);state.clearActionError();expect(state.actionError.value).toBe('');expect(await state.confirm()).toBeUndefined()
  expect(await state.save(incidentNote.id,incidentNoteChange)).toEqual(incidentNoteWithdrawn)
 })
 it('确定拒绝解除冻结，损坏回执或错误作者仍要求原请求核对',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new ApiError(409,'incident_conflict','修订已变化'));await state.save('',incidentNoteCreate);expect(state.unconfirmed.value).toBe(false)
  request.mockResolvedValueOnce({...incidentNote,spec:{...incidentNote.spec,body:'其他材料'}});await state.save('',incidentNoteCreate);expect(state.unconfirmed.value).toBe(true);expect(state.actionError.value).toContain('回执')
  request.mockResolvedValueOnce({...incidentNote,author_id:'user_other',actor_id:'user_other'});await state.confirm();expect(state.unconfirmed.value).toBe(true);request.mockResolvedValueOnce(incidentNote);await state.confirm();expect(state.unconfirmed.value).toBe(false)
 })
 it('身份撤销清除私有材料和待确认输入，不接受迟到的成功回执',async()=>{
  const {state}=host();await flushPromises();const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const saving=state.save('',incidentNoteCreate);const signal=request.mock.lastCall?.[1].signal as AbortSignal;(session.current as ShallowRef<Principal|null>).value=null;await flushPromises();expect(signal.aborted).toBe(true);late.resolve(incidentNote);expect(await saving).toBeUndefined();expect(state.page.value.items).toEqual([]);expect(state.pendingInput()).toBeUndefined()
 })
})

describe('调查笔记表单与独立工作区',()=>{
 it('原生表单提交校验真实输入，并使用当前事件修订',async()=>{
  const w=await form();await w.get('form').trigger('submit');await flushPromises();expect(w.emitted('save')).toBeUndefined();expect(document.activeElement?.getAttribute('aria-label')).toBe('笔记表单校验信息')
  await field('笔记标题',incidentNote.spec.title);await field('笔记正文',incidentNote.spec.body);await w.get('form').trigger('submit');await flushPromises();expect(w.emitted('save')?.[0]?.[0]).toEqual(incidentNoteCreate)
 })
 it('作者编辑和撤回必须提供说明，活动状态清空旧撤回原因',async()=>{
  const w=await form({record:incidentNote,editing:true});(w.vm as unknown as {submit:()=>void}).submit();await flushPromises();expect(w.emitted('save')).toBeUndefined();await field('笔记变更说明','补充来源');(w.vm as unknown as {submit:()=>void}).submit();expect(w.emitted('save')?.[0]?.[0]).toEqual({...incidentNoteCreate,expected_revision:1,reason:'补充来源'})
  w.findComponent(Select).vm.$emit('update:value','withdrawn');await flushPromises();(w.vm as unknown as {submit:()=>void}).submit();expect(w.emitted('save')).toHaveLength(1);await field('笔记撤回原因','引用待核实');(w.vm as unknown as {submit:()=>void}).submit();expect((w.emitted('save')?.[1]?.[0] as any).spec.withdrawal_reason).toBe('引用待核实')
  w.findComponent(Select).vm.$emit('update:value','active');await flushPromises();(w.vm as unknown as {submit:()=>void}).submit();expect((w.emitted('save')?.[2]?.[0] as any).spec.withdrawal_reason).toBe('')
 })
 it('确认冻结修订，忙碌、未知和结案状态不允许提交新材料',async()=>{
  const w=await form({record:incidentNote,editing:true,draft:incidentNoteChange,parent:{...incidentRecord,revision:9}});(w.vm as unknown as {submit:()=>void}).submit();expect(w.emitted('save')?.[0]?.[0]).toEqual(incidentNoteChange)
  for(const patch of [{busy:true},{busy:false,unconfirmed:true},{unconfirmed:false,parent:incidentClosed}]){await w.setProps(patch);(w.vm as unknown as {submit:()=>void}).submit();expect(w.emitted('save')).toHaveLength(1)}
 })
 it('列表、详情和历史只有一份笔记表格，正文按纯文本渲染',async()=>{
  const {state}=await modal();expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(1);await click('查看');expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0);expect(document.body.textContent).toContain(incidentNote.spec.body);await click('读取历史');expect(document.body.textContent).toContain('修订 2');expect(state.history.value).toHaveLength(2);expect(document.querySelector('.ant-modal script')).toBeNull();await click('返回笔记');expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(1)
 })
 it('同案关窗重开保留可见筛选，并重新读取匹配的笔记',async()=>{
  request.mockImplementation((path:string,options?:any)=>path.startsWith(root+'?')?Promise.resolve({items:[path.includes('status=withdrawn')?incidentNoteWithdrawn:incidentNote],next_cursor:''}):answer(path,options))
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');await click('调查笔记')
  const filter=w.findComponent(IncidentNotesModal).findComponent(Select)
  filter.vm.$emit('update:value','withdrawn');filter.vm.$emit('change','withdrawn');await flushPromises()
  expect(filter.props('value')).toBe('withdrawn');expect(w.findComponent(IncidentNotesModal).props('state').page.value.items[0]?.spec.status).toBe('withdrawn')
  await click('关闭');const count=request.mock.calls.filter(([path])=>path.startsWith(root+'?')).length
  await click(incidentRecord.spec.title);await click('调查笔记')
  const reopened=w.findComponent(IncidentNotesModal)
  expect(reopened.findComponent(Select).props('value')).toBe('withdrawn')
  expect(request.mock.calls.filter(([path])=>path.startsWith(root+'?'))).toHaveLength(count+1)
  expect(request.mock.calls.filter(([path])=>path.startsWith(root+'?')).at(-1)?.[0]).toBe(root+'?status=withdrawn&before=')
  expect(reopened.props('state').page.value.items[0]?.spec.status).toBe('withdrawn')
 })
 it('关窗取消列表读取，迟到材料不回填，同案重开重新读取',async()=>{
  const late=deferred<unknown>();let first=true
  request.mockImplementation((path:string,options?:any)=>{if(path.startsWith(root+'?')&&first){first=false;return late.promise}return answer(path,options)})
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');await click('调查笔记')
  const state=w.findComponent(IncidentNotesModal).props('state'),signal=request.mock.calls.find(([path])=>path.startsWith(root+'?'))?.[1].signal as AbortSignal
  expect(state.pending.value).toBe(true);await click('关闭');expect(signal.aborted).toBe(true)
  late.resolve(incidentNotePage);await flushPromises();expect(state.page.value.items).toEqual([]);expect(state.pending.value).toBe(false)
  const count=request.mock.calls.filter(([path])=>path.startsWith(root+'?')).length
  await click(incidentRecord.spec.title);await click('调查笔记')
  expect(request.mock.calls.filter(([path])=>path.startsWith(root+'?'))).toHaveLength(count+1)
  expect(w.findComponent(IncidentNotesModal).props('state').page.value.items).toEqual([incidentNote])
 })
 it('切换事件后恢复全部筛选，显示该事件的有效笔记',async()=>{
  const other:IncidentRecord={...incidentRecord,id:'incident_another',spec:{...incidentRecord.spec,title:'另一安全事件'}}
  const otherNote={...incidentNote,id:'case_note_another',incident_id:other.id,spec:{...incidentNote.spec,title:'另一事件的调查材料'}}
  request.mockImplementation((path:string,options?:any)=>{
   if(path.startsWith('/incidents?'))return Promise.resolve({items:[incidentRecord,other],next_cursor:''})
   if(path==='/incidents/'+other.id)return Promise.resolve(other)
   if(path.startsWith('/incidents/'+other.id+'/notes?'))return Promise.resolve({items:path.includes('status=withdrawn')?[]:[otherNote],next_cursor:''})
   if(path.startsWith(root+'?'))return Promise.resolve({items:[path.includes('status=withdrawn')?incidentNoteWithdrawn:incidentNote],next_cursor:''})
   return answer(path,options)
  })
  const w=mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click(incidentRecord.spec.title);await click('调查笔记')
  const filter=w.findComponent(IncidentNotesModal).findComponent(Select);filter.vm.$emit('update:value','withdrawn');filter.vm.$emit('change','withdrawn');await flushPromises()
  await click('关闭');await click(other.spec.title);await click('调查笔记')
  const opened=w.findComponent(IncidentNotesModal)
  expect(opened.findComponent(Select).props('value')).toBe('')
  expect(request.mock.calls.filter(([path])=>path.startsWith('/incidents/'+other.id+'/notes?')).at(-1)?.[0]).toBe('/incidents/'+other.id+'/notes?status=&before=')
  expect(opened.props('state').page.value.items).toEqual([otherNote]);expect(document.querySelector('.ant-modal')?.textContent).toContain(otherNote.spec.title)
 })
 it('建立笔记经保存入口提交，成功后刷新父事件与目录',async()=>{
  const {view}=await modal();await click('建立笔记');await field('笔记标题',incidentNote.spec.title);await field('笔记正文',incidentNote.spec.body);await click('保存笔记');expect(request.mock.calls.some(([p,o])=>p===root&&o?.method==='POST'&&o?.body.spec.body===incidentNote.spec.body)).toBe(true);expect(view.emitted('reloadParent')).toHaveLength(1);expect(document.body.textContent).toContain('建立笔记')
 })
 it('作者通过编辑入口撤回笔记，保留正文及独立变更说明',async()=>{
  const {view}=await modal();await click('查看');await click('编辑笔记');view.findComponent(Select).vm.$emit('update:value','withdrawn');await flushPromises();await field('笔记撤回原因',incidentNoteChange.spec.withdrawal_reason);await field('笔记变更说明',incidentNoteChange.reason);await click('保存笔记');expect(request.mock.calls.some(([p,o])=>p===root+'/'+incidentNote.id&&o?.method==='POST'&&JSON.stringify(o?.body)===JSON.stringify(incidentNoteChange))).toBe(true);expect(view.emitted('reloadParent')).toHaveLength(1)
 })
 it('空目录与读取失败分别展示，列表和详情可明确重试',async()=>{
  const {state}=await modal();request.mockResolvedValueOnce({items:[],next_cursor:''});await state.refresh();await flushPromises();expect(document.body.textContent).toContain('当前条件下没有调查笔记');request.mockRejectedValueOnce(new Error('来源暂不可用'));await state.refresh();await flushPromises();expect(document.body.textContent).toContain('来源暂不可用');await click('重试');request.mockRejectedValueOnce(new Error('笔记暂不可用'));await click('查看');expect(document.body.textContent).toContain('笔记暂不可用');await click('重试');expect(document.body.textContent).toContain(incidentNote.spec.body)
 })
 it('父事件刷新失败禁止新建并提供刷新入口，不掩盖原错误',async()=>{
  const {view}=await modal();await view.setProps({parentPending:true,parentError:'无法核对当前事件修订'});expect(button('建立笔记').disabled).toBe(true);expect(document.body.textContent).toContain('无法核对当前事件修订');await view.setProps({parentPending:false});await click('刷新事件与笔记');expect(view.emitted('reloadParent')).toHaveLength(1)
 })
 it('未知提交可关闭后恢复原材料并核对，同键确认后退出表单',async()=>{
  const {state,view}=await modal();await click('建立笔记');await field('笔记标题',incidentNote.spec.title);await field('笔记正文',incidentNote.spec.body);request.mockRejectedValueOnce(new Error('网络中断'));await click('保存笔记');expect(state.unconfirmed.value).toBe(true);expect(Array.from(document.querySelectorAll('button')).some(e=>e.textContent?.replace(/\s/g,'')==='保存笔记')).toBe(false)
  await click('关闭');expect(view.emitted('close')).toHaveLength(1);view.unmount();const reopened=mount(IncidentNotesModal,{props:{parent:incidentRecord,state,parentPending:false,parentError:''},global,attachTo:document.body});await flushPromises();expect((document.querySelector('[aria-label=\"笔记标题\"]') as HTMLInputElement).value).toBe(incidentNote.spec.title);await click('核对原提交',document.querySelector('.ant-modal-footer')!);expect(state.unconfirmed.value).toBe(false);expect(reopened.emitted('reloadParent')).toHaveLength(1)
 })
 it('结案禁止新建和编辑，其他作者笔记保持只读',async()=>{
  const closed=await modal(incidentClosed);expect(button('建立笔记').disabled).toBe(true);await click('查看');expect(button('编辑笔记').disabled).toBe(true);closed.view.unmount();closed.wrapper.unmount();document.body.replaceChildren()
  const opened=await modal();request.mockResolvedValueOnce({...incidentNote,author_id:'user_other',actor_id:'user_other'});await click('查看');expect(button('编辑笔记').disabled).toBe(true);expect(opened.state.selected.value?.author_id).toBe('user_other')
 })
 it('事件页面的笔记入口关闭调查详情，身份撤销退出私有笔记工作区',async()=>{
  mount(IncidentsWorkspace,{global,attachTo:document.body});await flushPromises();await click('查看');await click('调查笔记');expect(document.querySelectorAll('.ant-modal')).toHaveLength(1);expect(document.body.textContent).toContain('建立笔记');(session.current as ShallowRef<Principal|null>).value=null;await flushPromises();expect(document.body.textContent).not.toContain('建立笔记')
 })
})
