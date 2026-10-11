import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {flushPromises,mount} from '@vue/test-utils'
import {ApiError} from '../packages/shared/src/api'
import {registerAnt} from '../packages/shared/src/ant'
import {readSensorDirectory,validSensor} from '../packages/shared/src/sensors'
import {managementInputError,validGroupPage,validManagementReceipt,type GroupChange,type MetadataChange,type SensorGroup} from '../platform/src/features/sensors/management'
import {useSensorGroups} from '../platform/src/features/sensors/useSensorGroups'
import {useSensorMutation} from '../platform/src/features/sensors/useSensorMutation'
import ManagementForm from '../platform/src/features/sensors/ManagementForm.vue'
import {click,deferred,principal,sensor} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const group:SensorGroup={id:'sg_owned',revision:1,name:'办公站点',description:'',active:true,member_count:0,created_at:'2026-10-01T00:00:00Z',updated_at:'2026-10-01T00:00:00Z'}
const input:GroupChange={id:group.id,expected_revision:0,name:group.name,description:'',active:true}
const metadata:MetadataChange={expected_revision:1,registration_id:sensor.registration_id,name:'办公出口',description:'旁路',site:'机房',group_id:group.id}
function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));return {state,wrapper}}
beforeEach(()=>{request.mockReset();user.value=principal})

describe('探针目录和管理契约',()=>{
 it('拒绝损坏分页、越界修订和错误操作回执',()=>{
  expect(validGroupPage({items:[group],next_cursor:''})).toBe(true)
  for(const bad of [null,{}, {items:[group,group],next_cursor:''},{items:[{...group,member_count:-1}],next_cursor:''},{items:[group],next_cursor:'other'},{items:[{...group,updated_at:'bad'}],next_cursor:''}])expect(validGroupPage(bad)).toBe(false)
  expect(managementInputError(input)).toBe('');expect(managementInputError(metadata)).toBe('')
  expect(managementInputError({...input,name:'  '})).toContain('名称');expect(managementInputError({...input,expected_revision:1000000})).toContain('修订');expect(managementInputError({...input,id:'ungrouped'})).toContain('分组');expect(managementInputError({...input,active:false})).toContain('分组');expect(managementInputError({...metadata,registration_id:''})).toContain('注册');expect(managementInputError({...metadata,site:'a\nb'})).toContain('站点')
  expect(validManagementReceipt(group,'group',group.id,input)).toBe(true);expect(validManagementReceipt({...group,name:'changed'},'group',group.id,input)).toBe(false)
  const receipt={id:sensor.id,revision:2,...metadata,updated_at:group.updated_at};expect(validManagementReceipt(receipt,'metadata',sensor.id,metadata)).toBe(true);expect(validManagementReceipt({...receipt,registration_id:'changed'},'metadata',sensor.id,metadata)).toBe(false);expect(validManagementReceipt(receipt,'group',sensor.id,metadata)).toBe(false)
  expect(validSensor(sensor)).toBe(true);for(const bad of [null,[],{}, {...sensor,id:'a/b'},{...sensor,health:null},{...sensor,status:'unknown'}])expect(validSensor(bad)).toBe(false)
 })
 it('完整读取后续探针，重复、不前进和超额页面不得作为选项',async()=>{
  const second={...sensor,id:'probe_2'}
  const read=vi.fn().mockResolvedValueOnce({items:[sensor],next_cursor:sensor.id}).mockResolvedValueOnce({items:[second],next_cursor:''})
  const result=await readSensorDirectory({request:read},new AbortController().signal);expect(result.map(s=>s.id)).toEqual([sensor.id,second.id]);expect(read.mock.calls[1]?.[0]).toContain('cursor=probe_1')
  for(const invalid of [{items:[sensor,sensor],next_cursor:''},{items:[sensor],next_cursor:'bad/id'},{items:[sensor],next_cursor:'probe_2'},{items:new Array(101).fill(sensor),next_cursor:''},{items:[{}],next_cursor:''}])await expect(readSensorDirectory({request:vi.fn().mockResolvedValue(invalid)},new AbortController().signal)).rejects.toThrow('未能完整返回')
  read.mockReset().mockResolvedValueOnce({items:[sensor],next_cursor:sensor.id}).mockResolvedValueOnce({items:[sensor],next_cursor:sensor.id});await expect(readSensorDirectory({request:read},new AbortController().signal)).rejects.toThrow('未能完整返回')
 })
 it('目录请求取消后不继续读取或提交迟到的选项',async()=>{
  const controller=new AbortController();controller.abort();const read=vi.fn();await expect(readSensorDirectory({request:read},controller.signal)).rejects.toThrow('已取消');expect(read).not.toHaveBeenCalled()
  const live=new AbortController(),waiting=deferred<unknown>();read.mockReturnValue(waiting.promise);const promise=readSensorDirectory({request:read},live.signal);live.abort();waiting.resolve({items:[sensor],next_cursor:''});await expect(promise).rejects.toThrow('已取消')
 })
})

describe('分组目录与完整选项',()=>{
 it('分页、搜索和完整选项独立读取，旧请求不覆盖当前条件',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve({items:[group],next_cursor:path.includes('limit=20')?group.id:''}))
  const {state,wrapper}=host(useSensorGroups);await flushPromises();expect(state.page.value.items).toHaveLength(1);expect(state.choices.value).toEqual([group]);expect(state.pending.value).toBe(false)
  state.next();await flushPromises();expect(state.cursors.value).toHaveLength(2);expect(request.mock.calls.some(c=>c[0].includes('cursor=sg_owned'))).toBe(true);state.previous();await flushPromises();state.previous();expect(state.cursors.value).toEqual([''])
  state.search('办公','false');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('active=false')
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const first=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal;request.mockResolvedValue({items:[],next_cursor:''});state.search('新站点','true');await flushPromises();expect(signal.aborted).toBe(true);old.resolve({items:[group],next_cursor:''});await first;expect(state.page.value.items).toEqual([])
  const read=deferred<unknown>();request.mockReturnValue(read.promise);const choicesRead=state.loadChoices();const choiceSignal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(choiceSignal.aborted).toBe(true);read.resolve({items:[group],next_cursor:''});await choicesRead;expect(state.choices.value).toEqual([group]);await state.refresh();await state.loadChoices()
 })
 it('选项跨页重复、停用、非完整回执和错误均阻止编辑使用',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const {state}=host(useSensorGroups);await flushPromises()
  request.mockResolvedValueOnce({items:[group],next_cursor:group.id}).mockResolvedValueOnce({items:[group],next_cursor:''});await state.loadChoices();expect(state.choicesError.value).toContain('完整');expect(state.choices.value).toEqual([])
  request.mockResolvedValueOnce({items:[{...group,active:false}],next_cursor:''});await state.loadChoices();expect(state.choicesError.value).toContain('完整')
  request.mockResolvedValueOnce({items:[],next_cursor:'bad'});await state.refresh();expect(state.error.value).toContain('完整')
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('探针分组读取失败');request.mockRejectedValueOnce('offline');await state.loadChoices();expect(state.choicesError.value).toBe('可用探针分组读取失败')
  request.mockResolvedValue({items:[],next_cursor:''});user.value={...principal,tenant_id:'other'};await flushPromises();expect(state.page.value.items).toEqual([]);expect(state.cursors.value).toEqual([''])
 })
})

describe('管理提交与原请求确认',()=>{
 it('收到有效回执后才完成，服务错误和缺失回执保留相同输入与键',async()=>{
  const {state}=host(useSensorMutation);request.mockRejectedValueOnce(new Error('连接中断'))
  expect(await state.save('group',group.id,input)).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const first=request.mock.lastCall?.[1]
  const snapshot=state.pendingInput();expect(snapshot?.input).toEqual(input);expect(await state.save('group',group.id,{...input,name:'其他站点'})).toBeUndefined();expect(request).toHaveBeenCalledTimes(1)
  request.mockResolvedValueOnce({...group,revision:99});expect(await state.confirm()).toBeUndefined();expect(state.unconfirmed.value).toBe(true)
  request.mockResolvedValueOnce(group);expect(await state.confirm()).toEqual(group);expect(request.mock.lastCall?.[1].headers).toEqual(first.headers);expect(request.mock.lastCall?.[1].body).toEqual(first.body);expect(state.pendingInput()).toBeUndefined();expect(state.unconfirmed.value).toBe(false);expect(await state.confirm()).toBeUndefined()
 })
 it('明确冲突保留错误并解锁；并发、错误类型和离开后不提交',async()=>{
  const {state,wrapper}=host(useSensorMutation);request.mockRejectedValueOnce(new ApiError(409,'conflict','修订冲突'));expect(await state.save('group',group.id,input)).toBeUndefined();expect(state.unconfirmed.value).toBe(false);expect(state.error.value).toBe('修订冲突');state.clearError();expect(state.error.value).toBe('')
  expect(await state.save('metadata',sensor.id,input)).toBeUndefined();expect(state.error.value).toContain('类型');expect(await state.save('group',group.id,{...input,name:''})).toBeUndefined();expect(request).toHaveBeenCalledTimes(1)
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const saving=state.save('metadata',sensor.id,metadata);expect(await state.save('metadata',sensor.id,metadata)).toBeUndefined();const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);waiting.resolve({id:sensor.id,revision:2,...metadata,updated_at:group.updated_at});expect(await saving).toBeUndefined();expect(await state.save('metadata',sensor.id,metadata)).toBeUndefined()
 })
 it('超时不自动换键重试；身份变化清理未确认输入',async()=>{
  vi.useFakeTimers();const {state}=host(useSensorMutation),waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const saving=state.save('group',group.id,input);await vi.advanceTimersByTimeAsync(30001);waiting.resolve(group);await saving;expect(state.unconfirmed.value).toBe(true);expect(state.error.value).toContain('未确认');expect(request).toHaveBeenCalledTimes(1)
  state.clearError();expect(state.error.value).toContain('未确认');user.value={...principal,tenant_id:'other'};await flushPromises();expect(state.pendingInput()).toBeUndefined();expect(state.unconfirmed.value).toBe(false)
 })
})

describe('管理弹窗的实际交互',()=>{
 it('空字段取得错误焦点；创建和只读原提交恢复不丢失名称或标识',async()=>{
  const wrapper=mount(ManagementForm,{global:{plugins:[registerAnt]},props:{target:{kind:'group',record:null},groups:[],groupsPending:false,groupsError:'',busy:false,unconfirmed:false,error:''},attachTo:document.body})
  await click('保存');expect(document.body.textContent).toContain('请填写');expect(document.activeElement?.getAttribute('aria-label')).toBe('探针管理表单校验信息')
  const name=document.querySelector<HTMLInputElement>('#sensor-management-name')!;name.value='办公站点';name.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();await click('保存');await vi.waitFor(()=>expect(wrapper.emitted('save')?.[0]?.[2]).toMatchObject({expected_revision:0,name:'办公站点',active:true}))
  wrapper.unmount()
  const restored=mount(ManagementForm,{global:{plugins:[registerAnt]},props:{target:{kind:'group',record:null},draft:input,groups:[],groupsPending:false,groupsError:'',busy:false,unconfirmed:true,error:'连接中断'},attachTo:document.body});expect(document.querySelector<HTMLInputElement>('#sensor-management-name')?.value).toBe(input.name);await click('核对原提交');expect(restored.emitted('confirm')).toHaveLength(1);await click('关闭');expect(restored.emitted('close')).toHaveLength(1)
 })
 it('探针信息保持身份和管理修订，无可用分组时不提交',async()=>{
  const target={kind:'metadata' as const,record:{...sensor,metadata_revision:1,site:'原站点'}}
  const wrapper=mount(ManagementForm,{global:{plugins:[registerAnt]},props:{target,groups:[group],groupsPending:false,groupsError:'',busy:false,unconfirmed:false,error:''},attachTo:document.body})
  await click('保存');expect(document.body.textContent).toContain('没有可提交')
  const site=document.querySelector<HTMLInputElement>('#sensor-management-site')!;site.value='机房 B';site.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();await click('保存');expect(wrapper.emitted('save')?.[0]).toEqual(['metadata',sensor.id,{expected_revision:1,registration_id:sensor.registration_id,name:sensor.name,group_id:'',site:'机房 B',description:''}])
  await wrapper.setProps({groupsError:'分组读取失败'});expect(document.body.textContent).toContain('分组读取失败');await click('刷新分组');expect(wrapper.emitted('reloadGroups')).toHaveLength(1)
  await wrapper.setProps({busy:true,error:'修订冲突'});await flushPromises();expect(document.body.textContent).toContain('修订冲突');expect(document.querySelector<HTMLButtonElement>('button.ant-btn-primary')?.disabled).toBe(true)
 })
})

describe('探针分页与管理工作区',()=>{
 it('探针分页保持筛选条件，损坏响应保留最后有效列表',async()=>{
  const {useSensors}=await import('../platform/src/features/sensors/useSensors')
  const second={...sensor,id:'probe_2'}
  request.mockResolvedValueOnce({items:[sensor],next_cursor:sensor.id}).mockResolvedValueOnce({items:[second],next_cursor:''})
  const {state,wrapper}=host(useSensors);await flushPromises();expect(state.items.value).toEqual([sensor]);state.next();await flushPromises();expect(state.items.value).toEqual([second]);expect(state.cursors.value).toEqual(['',sensor.id]);state.next();expect(request).toHaveBeenCalledTimes(2)
  request.mockResolvedValueOnce({items:[sensor],next_cursor:''});state.previous();await flushPromises();state.previous();expect(state.cursors.value).toEqual([''])
  request.mockResolvedValueOnce({items:[sensor],next_cursor:''});state.search('  办公出口  ','sg_owned','online');await flushPromises();const query=new URLSearchParams(request.mock.lastCall?.[0].split('?')[1]);expect(query.get('keyword')).toBe('办公出口');expect(query.get('group_id')).toBe('sg_owned');expect(query.get('status')).toBe('online')
  for(const bad of [{items:[sensor,sensor],next_cursor:''},{items:[second,sensor],next_cursor:''},{items:[sensor],next_cursor:'probe_2'},{items:[{}],next_cursor:''},{items:new Array(21).fill(sensor),next_cursor:''}]){request.mockResolvedValueOnce(bad);await state.refresh();expect(state.error.value).toContain('未能完整返回');expect(state.items.value).toEqual([sensor])}
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;request.mockResolvedValue({items:[],next_cursor:''});user.value={...principal,tenant_id:'other'};await flushPromises();expect(signal.aborted).toBe(true);late.resolve({items:[sensor],next_cursor:''});await reading;expect(state.items.value).toEqual([]);expect(state.cursors.value).toEqual(['']);wrapper.unmount();await state.refresh();expect(await state.toggle(sensor)).toBe(false)
 })
 it('分组成员与编辑操作独立，只读和未确认状态限制写操作',async()=>{
  const {default:GroupTable}=await import('../platform/src/features/sensors/GroupTable.vue')
  const disabled={...group,id:'sg_empty',name:'备用站点',active:false,member_count:0}
  const wrapper=mount(GroupTable,{global:{plugins:[registerAnt]},props:{items:[{...group,member_count:2},disabled],admin:true,locked:false},attachTo:document.body})
  expect(wrapper.text()).toContain('备用站点');expect(wrapper.text()).toContain('停用');await click('2台');expect(wrapper.emitted('members')?.[0]?.[0]).toMatchObject({id:group.id,member_count:2});await click('编辑');expect(wrapper.emitted('edit')?.[0]?.[0]).toMatchObject({id:group.id})
  await wrapper.setProps({locked:true});expect(Array.from((wrapper.element as HTMLElement).querySelectorAll<HTMLButtonElement>('button')).find(b=>b.textContent?.trim()==='编辑')?.disabled).toBe(true)
  await wrapper.setProps({admin:false});expect(wrapper.text()).not.toContain('编辑');await click('查看探针');expect(wrapper.emitted('members')).toHaveLength(2)
 })
 it('分组工作区恢复原提交，确认后同步列表，成员跳转保留分组筛选',async()=>{
  const{createRouter,createMemoryHistory}=await import('vue-router'),{default:Workspace}=await import('../platform/src/features/sensors/SensorsWorkspace.vue')
  let savedGroup=group,fail=true
  request.mockImplementation((path:string,options?:{method?:string;body?:GroupChange})=>{
   if(options?.method==='POST'){if(fail)return Promise.reject(new Error('连接中断'));savedGroup={...group,...options.body!,revision:1};return Promise.resolve(savedGroup)}
   if(path.startsWith('/sensor-groups'))return Promise.resolve({items:[savedGroup],next_cursor:''})
   return Promise.resolve({items:[{...sensor,metadata_revision:1}],next_cursor:''})
  })
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/sensors',component:Workspace}]});await router.push('/sensors?view=groups');await router.isReady()
  const wrapper=mount(Workspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  await click('创建分组');const name=document.querySelector<HTMLInputElement>('#sensor-management-name')!;name.value='分支园区';name.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();await click('保存');await vi.waitFor(()=>expect(document.body.textContent).toContain('结果尚未确认'))
  const original=request.mock.calls.find(c=>c[1]?.method==='POST')!;await click('关闭');await click('核对原提交');expect(document.querySelector<HTMLInputElement>('#sensor-management-name')?.value).toBe('分支园区')
  fail=false;await click('核对原提交',document.querySelector('.ant-modal')!);await vi.waitFor(()=>expect(document.querySelector('.ant-modal')).toBeNull());const submitted=request.mock.calls.filter(c=>c[1]?.method==='POST');expect(submitted).toHaveLength(2);expect(submitted[1]?.[1].headers).toEqual(original[1].headers);expect(submitted[1]?.[1].body).toEqual(original[1].body)
  await click('查看探针');expect(router.currentRoute.value.query.view).toBeUndefined();expect(request.mock.calls.some(c=>c[0].startsWith('/sensors?')&&new URLSearchParams(c[0].split('?')[1]).get('group_id')===savedGroup.id)).toBe(true);expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  await click('重置');expect(request.mock.lastCall?.[0]).toContain('group_id=');await click('编辑');expect(document.body.textContent).toContain('探针名称');await click('关闭')
  await click('探针分组');await click('刷新');expect(wrapper.text()).toContain('分支园区');await click('重置');expect(request.mock.calls.some(c=>c[0].startsWith('/sensor-groups?')&&c[0].includes('keyword=&active='))).toBe(true)
  user.value={...principal,tenant_id:'other'};await flushPromises();expect(document.querySelector('.ant-modal')).toBeNull();wrapper.unmount()
 })
})
