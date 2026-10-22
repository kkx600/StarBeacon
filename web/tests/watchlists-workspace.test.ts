import {webcrypto,randomUUID} from 'node:crypto'
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {Select,Form} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {watchlistDefinitionShape,type WatchlistChange,type WatchlistPreviewRequest,type WatchlistRecord} from '../packages/shared/src/watchlists'
import WatchlistForm from '../packages/shared/src/components/WatchlistForm.vue'
import WatchlistDetail from '../packages/shared/src/components/WatchlistDetail.vue'
import WatchlistPreview from '../packages/shared/src/components/WatchlistPreview.vue'
import WatchlistTable from '../packages/shared/src/components/WatchlistTable.vue'
import WatchlistPreviewResultView from '../packages/shared/src/components/WatchlistPreviewResult.vue'
import WatchlistsWorkspace from '../platform/src/features/watchlists/WatchlistsWorkspace.vue'
import WatchlistsView from '../platform/src/views/WatchlistsView.vue'
import {useWatchlists} from '../platform/src/features/watchlists/useWatchlists'
import {useWatchlistPreview} from '../platform/src/features/watchlists/useWatchlistPreview'
import {useWatchlistSensors} from '../platform/src/features/watchlists/useWatchlistSensors'
import {watchlistInput,watchlistPreview,watchlistRecord} from './watchlistFixtures'
import {principal,sensor,click,deferred} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef<typeof principal|null>(principal),wrappers:VueWrapper[]=[]
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const body=()=>new DOMWrapper(document.body)
const directory=[{sensor_id:sensor.id,registration_id:sensor.registration_id,name:sensor.name,available:true}]
let row:WatchlistRecord
function good(){request.mockImplementation(async(path:string,options?:{method?:string;body?:unknown})=>{
 if(path.startsWith('/sensors'))return {items:[sensor],next_cursor:''}
 if(path.endsWith('/preview'))return watchlistPreview(options?.body as WatchlistPreviewRequest)
 if(path.includes('/revisions/'))return row
 if(options?.method==='POST'){row=await watchlistRecord(options.body as WatchlistChange);return row}
 return {items:[row],next_cursor:''}
})}
async function screen(component:Parameters<typeof mount>[0]=WatchlistsWorkspace){const w=mount(component,{attachTo:document.body,global:{plugins:[registerAnt]}});wrappers.push(w);await vi.waitFor(()=>expect(w.find('.ant-spin-spinning').exists()).toBe(false));await flushPromises();return w}
// 表单关闭表示写入回执已确认；目录仍须完成独立读取与摘要核验。
async function settledDirectory(w:VueWrapper,record:WatchlistRecord){await vi.waitFor(()=>{expect(w.get('.page-header button').classes()).not.toContain('ant-btn-loading');expect(w.getComponent(WatchlistTable).props('items')).toEqual([record])})}
function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));wrappers.push(wrapper);return {state,wrapper}}
async function form(extra:Record<string,unknown>={}){const w=mount(WatchlistForm,{attachTo:document.body,props:{record:row,busy:false,unconfirmed:false,error:'',sensors:directory,...extra},global:{plugins:[registerAnt]}});wrappers.push(w);await flushPromises();return w}
function select(w:VueWrapper,id:string,value:unknown){const component=w.findAllComponents(Select).find(c=>c.attributes('id')===id||c.find('#'+id).exists());expect(component,`选择器 ${id}`).toBeDefined();component!.vm.$emit('update:value',value)}
beforeEach(async()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID});vi.spyOn(Date,'now').mockReturnValue(Date.parse('2026-10-22T00:00:00Z'));row=await watchlistRecord();good()})
afterEach(()=>{wrappers.splice(0).forEach(w=>w.unmount());vi.useRealTimers();document.body.replaceChildren();vi.unstubAllGlobals()})

describe('名单目录与冻结提交',()=>{
 it('稳定游标按同一条件续页，切换筛选取消旧读取',async()=>{
  const rows=Array.from({length:20},(_,i)=>({...row,id:'watch_'+String(i).padStart(2,'0')})),q={cursor:'',keyword:'',active:'',kind:'',limit:20}
  const token=btoa(JSON.stringify({after:rows.at(-1)!.id,scope:await goJSONDigest({tenant:principal.tenant_id,query:q})})).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
  request.mockResolvedValue({items:rows,next_cursor:token});const {state}=host(useWatchlists);await vi.waitFor(()=>expect(state.page.value.items).toHaveLength(20))
  request.mockResolvedValue({items:[],next_cursor:''});state.next();await vi.waitFor(()=>expect(state.pending.value).toBe(false));expect(state.cursors.value).toHaveLength(2);state.next();expect(state.cursors.value).toHaveLength(2);state.previous();await flushPromises();expect(state.cursors.value).toEqual(['']);state.previous()
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.search('  关注  ','false','observe');await flushPromises();expect(signal.aborted).toBe(true);expect(request.mock.lastCall?.[0]).toContain('kind=observe');expect(state.query.value.keyword).toBe('关注');old.resolve({items:[row],next_cursor:''});await reading;expect(state.page.value.items).toEqual([])
 })
 it('未知提交只能按原键确认，错误回执不会被当作保存成功',async()=>{
  const {state}=host(useWatchlists);await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));expect(await state.save(watchlistInput())).toBeUndefined();const first=request.mock.lastCall?.[1];expect(state.unconfirmed.value).toBe(true);expect(state.draft()).toEqual(watchlistInput())
  expect(await state.save({...watchlistInput(),name:'另一请求'})).toBeUndefined();expect(state.mutationError.value).toContain('核对原提交');state.clearError();expect(state.mutationError.value).not.toBe('')
  request.mockResolvedValueOnce({});await state.confirm();expect(state.unconfirmed.value).toBe(true);request.mockResolvedValueOnce(row);expect(await state.confirm()).toEqual(row);expect(request.mock.lastCall?.[1].headers).toEqual(first.headers);expect(state.unconfirmed.value).toBe(false);expect(state.draft()).toBeUndefined();state.clearError();expect(state.mutationError.value).toBe('');expect(await state.confirm()).toBeUndefined()
 })
 it('冲突和无效输入不锁死草稿，撤权清除输入并取消在途写入',async()=>{
  const {state}=host(useWatchlists);await flushPromises();await state.save({...watchlistInput(),description:''});expect(state.mutationError.value).toContain('依据');request.mockRejectedValueOnce(new ApiError(409,'watchlist_conflict','旧修订'));await state.save(watchlistInput());expect(state.unconfirmed.value).toBe(false);expect(state.mutationError.value).toContain('注册已变化')
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const saving=state.save(watchlistInput()),signal=request.mock.lastCall?.[1].signal as AbortSignal;expect(state.busy.value).toBe(true);expect(await state.save(watchlistInput())).toBeUndefined();user.value={...principal,role:'viewer'};await flushPromises();expect(signal.aborted).toBe(true);expect(state.draft()).toBeUndefined();waiting.resolve(row);expect(await saving).toBeUndefined();await state.save(watchlistInput());expect(state.mutationError.value).toContain('无权')
 })
 it('超时显示未确认；同一提交跨业务到期仍可回读原结果',async()=>{
  const {state}=host(useWatchlists);await flushPromises();const input=watchlistInput();input.active=true;input.definition.valid_until='2026-10-22T00:01:00Z';const receipt=await watchlistRecord(input),waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise)
  vi.useFakeTimers();const saved=state.save(input);await vi.advanceTimersByTimeAsync(30001);waiting.reject(new Error('timeout'));await saved;expect(state.unconfirmed.value).toBe(true);vi.spyOn(Date,'now').mockReturnValue(Date.parse('2026-10-22T00:02:00Z'));request.mockResolvedValueOnce(receipt);expect(await state.confirm()).toEqual(receipt);vi.useRealTimers()
 })
 it('身份变化和卸载拒绝迟到目录，读取超时保留错误而非空成功',async()=>{
  const {state,wrapper}=host(useWatchlists);await flushPromises();const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const reading=state.refresh();user.value=null;old.resolve({items:[row],next_cursor:''});await reading;expect(state.page.value.items).toEqual([]);await state.refresh();user.value=principal;await flushPromises()
  const timeout=deferred<unknown>();request.mockReturnValueOnce(timeout.promise);vi.useFakeTimers();const failed=state.refresh();await vi.advanceTimersByTimeAsync(30001);timeout.reject(new Error('timeout'));await failed;expect(state.error.value).toContain('读取超时');vi.useRealTimers()
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const last=state.refresh();wrapper.unmount();late.resolve({items:[row],next_cursor:''});await last;expect(await state.save(watchlistInput())).toBeUndefined();await state.refresh()
 })
})

describe('名单范围与探针目录',()=>{
 it('预览取消、重试、权限变化及超时不会复活旧结果',async()=>{
  const {state,wrapper}=host(useWatchlistPreview),input={definition:watchlistDefinitionShape(row.definition),active:false,targets:[]}
  await state.run(input);expect(state.result.value?.admissible).toBe(true);const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const reading=state.run(input),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.clear();expect(signal.aborted).toBe(true);late.resolve(await watchlistPreview(input));await reading;expect(state.result.value).toBeNull()
  request.mockRejectedValueOnce(new Error('暂不可用'));await state.run(input);expect(state.error.value).toContain('暂不可用');await state.retry();expect(state.result.value).not.toBeNull();await state.run({...input,definition:{...input.definition,values:[]}});expect(state.error.value).toContain('1–64')
  const timeout=deferred<unknown>();request.mockReturnValueOnce(timeout.promise);vi.useFakeTimers();const slow=state.run(input);await vi.advanceTimersByTimeAsync(30001);timeout.reject(new Error('timeout'));await slow;expect(state.error.value).toContain('核验超时');vi.useRealTimers();user.value={...principal,role:'viewer'};await flushPromises();await state.run(input);expect(state.result.value).toBeNull();wrapper.unmount();await state.run(input);await state.retry()
 })
 it('探针选择读取完整分页目录，只提供当前启用身份并保留失败',async()=>{
  const {state,wrapper}=host(useWatchlistSensors);await state.refresh();expect(state.items.value).toEqual(directory);request.mockResolvedValueOnce({items:[{...sensor,active:false}],next_cursor:''});await state.refresh();expect(state.items.value).toEqual([])
  request.mockRejectedValueOnce(new Error('目录错误'));await state.refresh();expect(state.error.value).toContain('目录错误');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value=null;await flushPromises();expect(signal.aborted).toBe(true);late.resolve({items:[sensor],next_cursor:''});await reading;expect(state.items.value).toEqual([]);user.value=principal;await flushPromises()
  const timeout=deferred<unknown>();request.mockReturnValueOnce(timeout.promise);vi.useFakeTimers();const slow=state.refresh();await vi.advanceTimersByTimeAsync(30001);timeout.reject(new Error('timeout'));await slow;expect(state.error.value).toContain('探针目录读取超时');vi.useRealTimers();wrapper.unmount();await state.refresh()
 })
})

describe('名单表单与单表目录交互',()=>{
 it('选择与日期控件的Escape不冒泡关闭表单，依据保持单行输入',async()=>{
  const w=await form(),escaped=vi.fn();document.body.addEventListener('keydown',escaped)
  try{for(const id of ['watchlist-active','watchlist-kind','watchlist-match-type','watchlist-sensors','watchlist-valid-from','watchlist-valid-until'])await body().get('#'+id).trigger('keydown',{key:'Escape',code:'Escape',keyCode:27});expect(escaped).not.toHaveBeenCalled();expect(w.emitted('close')).toBeUndefined();expect(body().get('#watchlist-description').element.tagName).toBe('INPUT')}
  finally{document.body.removeEventListener('keydown',escaped)}
 })
 it('真实DOM提交保留scope和原始修订，必填依据失败定位错误',async()=>{
  const w=await form();await body().get('#watchlist-description').setValue('');await body().get('form').trigger('submit');await vi.waitFor(()=>expect(body().text()).toContain('必填依据'));expect(w.emitted('save')).toBeUndefined();await body().get('#watchlist-description').setValue('人工核对后的保护依据');await body().get('#watchlist-name').setValue('业务管理地址');await body().get('form').trigger('submit');await vi.waitFor(()=>expect(w.emitted('save')).toHaveLength(1));const submitted=w.emitted('save')![0]![0] as WatchlistChange;expect(submitted.expected_revision).toBe(1);expect(submitted.definition.sensors).toEqual(row.definition.sensors);expect(submitted.definition.valid_from).toBe(row.definition.valid_from);expect(submitted.active).toBe(false)
 })
 it('启用需要当前范围核验，变化清除核验但维护名称不使其失效',async()=>{
  const w=await form();select(w,'watchlist-active','true');await flushPromises();await click('保存名单');expect(body().text()).toContain('启用前请执行范围核验');await click('范围核验');const input=w.emitted('preview')![0]![0] as WatchlistPreviewRequest;expect(input.active).toBe(true);await w.setProps({preview:await watchlistPreview(input)});const previous=w.emitted('change')?.length??0;await body().get('#watchlist-name').setValue('新的名称');expect(w.emitted('change')?.length??0).toBe(previous);await click('保存名单');expect(w.emitted('save')).toHaveLength(1)
  await body().get('#watchlist-values').setValue('198.51.100.20');expect(w.emitted('change')!.length).toBeGreaterThan(previous)
 })
 it('未知提交锁定字段并保留原请求入口，刷新探针和关闭有明确事件',async()=>{
  const w=await form({unconfirmed:true,error:'原提交尚未确认'});expect(body().get('#watchlist-name').attributes('disabled')).toBeDefined();await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);expect(w.emitted('save')).toBeUndefined();await click('关闭');expect(w.emitted('close')).toHaveLength(1)
  await w.setProps({unconfirmed:false,sensors:[],sensorsError:'探针读取失败'});expect(body().text()).toContain('当前注册不可用');await click('刷新探针');expect(w.emitted('refreshSensors')).toHaveLength(1);await w.setProps({sensorsError:'',busy:true});w.getComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('save')).toBeUndefined()
 })
 it('新建名单没有默认scope，不会误把首个探针自动授权',async()=>{
  const w=await form({record:null});await body().get('#watchlist-name').setValue('候选名单');await body().get('#watchlist-description').setValue('受控范围依据');await body().get('#watchlist-values').setValue('192.0.2.10');await click('范围核验');expect(body().text()).toContain('请选择 1–32');select(w,'watchlist-sensors',['probe_1/register_1']);await flushPromises();await click('保存名单');expect(w.emitted('save')).toHaveLength(1)
 })
 it('目录、筛选、修订和材料核验分别操作，始终只有一张业务表',async()=>{
  const w=await screen();expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);await w.get('input[aria-label="筛选名单名称"]').setValue('办公');await w.get('form').trigger('submit');await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1));expect(request.mock.calls.some(c=>String(c[0]).includes('keyword='))).toBe(true);await click('重置');await click('刷新目录');await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1));await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('定义 SHA-256'));expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);await click('关闭');await click('范围核验');await vi.waitFor(()=>expect(body().text()).toContain('当前范围允许启用'));expect(body().text()).toContain('不查询全部历史流量');await body().get('#watchlist-test-values').setValue('192.0.2.10');await click('执行核验');await vi.waitFor(()=>expect(body().text()).toContain('材料匹配'));expect(body().text()).toContain('名单当前未生效');await click('关闭');expect(w.findComponent(WatchlistPreview).exists()).toBe(false)
 })
 it('停用入口冻结定义，保存后返回目录；更新失败保留上次结果与真实错误',async()=>{
  row=await watchlistRecord({...watchlistInput(),active:true});const w=await screen();await click('停用');await vi.waitFor(()=>expect(w.getComponent(WatchlistForm).props('sensorsPending')).toBe(false));expect(w.getComponent(WatchlistForm).props('draft')?.active).toBe(false);await click('保存名单');await vi.waitFor(()=>expect(w.findComponent(WatchlistForm).exists()).toBe(false));expect(row.active).toBe(false)
  await settledDirectory(w,row)
  request.mockRejectedValueOnce(new Error('服务暂不可用'));await click('刷新目录');await vi.waitFor(()=>expect(w.text()).toContain('更新失败'));expect(w.text()).toContain('服务暂不可用');expect(w.findAll('.ant-table-wrapper')).toHaveLength(1)
 })
 it('写入回执与目录读取分别完成，延迟目录核验后查看当前修订',async()=>{
  const w=await screen(),previous=structuredClone(row),directoryRead=deferred<unknown>(),respond=request.getMockImplementation()!
  await settledDirectory(w,previous)
  request.mockImplementation((path:string,options?:{method?:string;body?:unknown})=>path.startsWith('/watchlists?')?directoryRead.promise:respond(path,options))
  await click('编辑');await vi.waitFor(()=>expect(w.getComponent(WatchlistForm).props('sensorsPending')).toBe(false));await click('保存名单');await vi.waitFor(()=>expect(w.findComponent(WatchlistForm).exists()).toBe(false))
  expect(row.revision).toBe(previous.revision+1);expect(w.getComponent(WatchlistTable).props('items')).toEqual([previous]);expect(w.get('.page-header button').classes()).toContain('ant-btn-loading')
  const reads=request.mock.calls.filter(c=>String(c[0]).startsWith('/watchlists?')).length
  await click('刷新目录');expect(request.mock.calls.filter(c=>String(c[0]).startsWith('/watchlists?'))).toHaveLength(reads)
  directoryRead.resolve({items:[row],next_cursor:''});await settledDirectory(w,row);await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('定义 SHA-256'));expect(request.mock.calls.filter(c=>String(c[0]).includes('/revisions/')).at(-1)?.[0]).toBe(`/watchlists/${row.id}/revisions/${row.revision}`)
 })
 it('未知提交关闭后按原键确认；账户变化关闭所有旧身份内容',async()=>{
  const w=await screen(WatchlistsView);await click('编辑');await vi.waitFor(()=>expect(w.getComponent(WatchlistForm).props('sensorsPending')).toBe(false));const input={...watchlistInput(),expected_revision:row.revision};request.mockRejectedValueOnce(new Error('未收到回执'));w.getComponent(WatchlistForm).vm.$emit('save',input);await vi.waitFor(()=>expect(body().text()).toContain('未收到回执'));await click('关闭');await click('核对原提交');await vi.waitFor(()=>expect(w.getComponent(WatchlistForm).props('sensorsPending')).toBe(false));await click('核对原提交',document.querySelector('.ant-modal')!);await vi.waitFor(()=>expect(w.findComponent(WatchlistForm).exists()).toBe(false));const posts=request.mock.calls.filter(c=>c[0]==='/watchlists'&&c[1]?.method==='POST');expect(posts).toHaveLength(2);expect(posts[0]![1].headers).toEqual(posts[1]![1].headers);expect(posts[0]![1].body).toEqual(posts[1]![1].body)
  await settledDirectory(w,row);await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('定义 SHA-256'));expect(request.mock.calls.filter(c=>String(c[0]).includes('/revisions/')).at(-1)?.[0]).toBe(`/watchlists/${row.id}/revisions/${row.revision}`);user.value={...principal,role:'viewer'};await flushPromises();expect(w.findComponent(WatchlistDetail).exists()).toBe(false);expect(w.text()).not.toContain('创建名单');expect(w.text()).not.toContain('编辑')
 })
 it('原提交未确认时查看与其他行操作均真实禁用，并说明恢复入口',async()=>{
  const w=await screen();await click('编辑');await vi.waitFor(()=>expect(w.getComponent(WatchlistForm).props('sensorsPending')).toBe(false))
  request.mockRejectedValueOnce(new Error('提交回执中断'));w.getComponent(WatchlistForm).vm.$emit('save',{...watchlistInput(),expected_revision:row.revision});await vi.waitFor(()=>expect(body().text()).toContain('提交回执中断'));await click('关闭')
  const actions=w.findAll('.watchlist-actions button');expect(actions).toHaveLength(4)
  for(const action of actions)expect((action.element as HTMLButtonElement).disabled,`${action.text()}应遵守原提交锁定`).toBe(true)
  expect(w.text()).toContain('请点击“核对原提交”');expect(w.text()).toContain('再查看或维护其他名单')
  const reads=request.mock.calls.filter(c=>String(c[0]).includes('/revisions/')).length
  ;(actions[0]!.element as HTMLButtonElement).click();await flushPromises();expect(request.mock.calls.filter(c=>String(c[0]).includes('/revisions/'))).toHaveLength(reads)
  await click('核对原提交');expect(w.getComponent(WatchlistForm).props('unconfirmed')).toBe(true);expect(w.getComponent(WatchlistForm).props('draft')?.expected_revision).toBe(row.revision);expect(request.mock.calls.filter(c=>c[0]==='/watchlists'&&c[1]?.method==='POST')).toHaveLength(1)
 })
 it('历史加载错误不显示旧证据，关闭取消并拒绝迟到修订',async()=>{
  const w=await screen();await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('定义 SHA-256'));request.mockResolvedValueOnce({...row,id:'other'});w.getComponent(WatchlistDetail).vm.$emit('read',1);await vi.waitFor(()=>expect(body().text()).toContain('所选记录不一致'));expect(body().text()).not.toContain(row.definition_sha256)
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);w.getComponent(WatchlistDetail).vm.$emit('read',1);await flushPromises();const signal=request.mock.lastCall?.[1].signal as AbortSignal;await click('关闭');expect(signal.aborted).toBe(true);late.resolve(row);await flushPromises();expect(w.findComponent(WatchlistDetail).exists()).toBe(false)
 })
 it('空目录与加载错误分开，查看账号不能创建或操作名单',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const w=await screen();expect(w.text()).toContain('当前条件下没有名单');request.mockRejectedValueOnce(new Error('读取失败'));await click('刷新目录');expect(w.text()).toContain('读取失败');expect(w.text()).not.toContain('当前条件下没有名单');good();user.value={...principal,role:'viewer'};await vi.waitFor(()=>expect(w.findComponent(WatchlistTable).exists()).toBe(true));expect(w.findComponent(WatchlistTable).props('canEdit')).toBe(false);expect(w.text()).not.toContain('创建名单')
 })
})

describe('独立修订与材料输入边界',()=>{
 it('修订输入限制上下界，关闭与重试不混入第二张列表',async()=>{
  const w=mount(WatchlistDetail,{attachTo:document.body,props:{record:row,revision:1,maximum:2},global:{plugins:[registerAnt]}});wrappers.push(w);await click('读取');expect(w.emitted('read')).toEqual([[1]]);await w.setProps({revision:2});await flushPromises();await click('读取');expect(w.emitted('read')!.at(-1)).toEqual([2]);expect(body().findAll('.ant-table-wrapper')).toHaveLength(0);await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('非法材料和超限拒绝运行，范围变更请求清除旧结论',async()=>{
  const w=mount(WatchlistPreview,{attachTo:document.body,props:{record:row,result:null,pending:false,error:''},global:{plugins:[registerAnt]}});wrappers.push(w);await body().get('#watchlist-test-values').setValue('not-an-ip');await click('执行核验');expect(body().text()).toContain('规范值');expect(w.emitted('run')).toBeUndefined();await body().get('#watchlist-test-values').setValue('192.0.2.10');await click('执行核验');const input=w.emitted('run')![0]![0] as WatchlistPreviewRequest;await w.setProps({input,result:await watchlistPreview(input)});expect(body().text()).toContain('材料匹配');expect(w.emitted('change')).toBeTruthy();await w.setProps({pending:true});w.getComponent(Form).vm.$emit('finish');await flushPromises();expect(w.emitted('run')).toHaveLength(1)
 })
 it('结果区区分过宽、停用、当前有效与无材料，不包含设备成功结论',async()=>{
  const input={definition:watchlistDefinitionShape(row.definition),active:true,targets:[]},result=await watchlistPreview(input),w=mount(WatchlistPreviewResultView,{props:{result},global:{plugins:[registerAnt]}});wrappers.push(w);expect(w.text()).toContain('处于有效期内且已启用');expect(w.text()).toContain('不授予设备执行权限');const broad={...input,active:false,definition:{...input.definition,match_type:'cidr' as const,values:['192.0.0.0/16']}};await w.setProps({result:await watchlistPreview(broad)});expect(w.text()).toContain('当前范围不能启用');expect(w.text()).toContain('CIDR 范围超过启用限制')
 })
})
