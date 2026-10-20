import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {registerAnt} from '../packages/shared/src/ant'
import {defaultResponseFilters,responseQuery,readResponsePage,type ResponseQuery,type ResponsePage} from '../packages/shared/src/responseCatalog'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import type {Principal,SensorTask} from '../packages/shared/src/types'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import ResponseActionsView from '../platform/src/views/ResponseActionsView.vue'
import {session} from '../platform/src/session'
import {ApiError} from '../packages/shared/src/api'
import {click,deferred,principal,sensor} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>,wrappers:VueWrapper[]=[]
const object=(query:ResponseQuery)=>({...query,start:query.start.replace('.000Z','Z'),end:query.end.replace('.000Z','Z')})
function responseTask(id='task_owned'):SensorTask{
 const now=Date.now();return {id,sensor_id:sensor.id,kind:'response.block',state:'unknown',created_by:principal.id,created_at:new Date(now-3600000).toISOString(),updated_at:new Date(now-3500000).toISOString(),expires_at:new Date(now-3540000).toISOString(),retain_until:new Date(now+180*86400000).toISOString(),delivery_count:1,receipt:{},response_action:{schema_version:'response.action.v1',connector_id:'connector_owned',device_id:'device_owned',config_sha256:'a'.repeat(64),lease_id:id,owner_sha256:'b'.repeat(64),target_ip:'198.51.100.24',requested_at:new Date(now-3600000).toISOString(),expires_at:new Date(now-3300000).toISOString(),reason:'明确核验依据'}}
}
function query():ResponseQuery{return responseQuery(defaultResponseFilters())}
async function token(q:ResponseQuery,row:SensorTask){const echo=object(q);return btoa(JSON.stringify({time:row.created_at.replace('.000Z','Z'),id:row.id,query:await goJSONDigest({start:echo.start,end:echo.end,sensor_id:q.sensor_id,kind:q.kind,state:q.state,target_ip:q.target_ip,device_id:q.device_id,cursor:'',limit:q.limit})})).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')}
function responsePage(q:ResponseQuery,items:SensorTask[]=[]):ResponsePage{return {items,next_cursor:'',query:object(q),observed_at:new Date().toISOString()}}
function fromPath(path:string):ResponseQuery{const params=new URLSearchParams(path.split('?')[1]);return Object.fromEntries([...params].map(([key,value])=>[key,key==='limit'?Number(value):value])) as unknown as ResponseQuery}
beforeEach(()=>{vi.clearAllMocks();user.value=principal})
afterEach(()=>{for(const wrapper of wrappers.splice(0))wrapper.unmount();document.body.innerHTML='';vi.useRealTimers()})

describe('响应动作检索与来源核对',()=>{
 it('默认固定近一天窗口并拒绝无效时间或标识',()=>{
  const value=defaultResponseFilters(),q=responseQuery(value);expect(Date.parse(q.end)-Date.parse(q.start)).toBe(86400000)
  for(const change of [{start:'bad'},{end:value.start},{start:'2000-01-01T00:00:00'},{end:'2099-01-01T00:00:00'},{sensor_id:'UPPER'},{device_id:'bad/id'}])expect(()=>responseQuery({...value,...change})).toThrow()
 })
 it('分页按纳秒与标识比较，核对窗口回显、完整续页与精确筛选',async()=>{
  const q=query();q.limit=2;const a=responseTask('task_b'),b=responseTask('task_a');b.created_at=a.created_at
  const page=responsePage(q,[a,b]);page.next_cursor=await token(q,b);expect((await readResponsePage(page,q)).items).toHaveLength(2)
  const next={...q,cursor:page.next_cursor};const c=responseTask('task_0');c.created_at=a.created_at;expect((await readResponsePage(responsePage(next,[c]),next)).items[0]?.id).toBe('task_0')
  const exact={...q,sensor_id:a.sensor_id,device_id:a.response_action!.device_id,target_ip:a.response_action!.target_ip,kind:a.kind,state:a.state};expect((await readResponsePage(responsePage(exact,[a]),exact)).items).toHaveLength(1)
  a.created_at=a.created_at.replace(/\.\d{3}Z$/,'.000002Z');b.created_at=a.created_at.replace('.000002Z','.000001Z');a.id='task_a';a.response_action!.lease_id=a.id;b.id='task_z';b.response_action!.lease_id=b.id
  expect((await readResponsePage(responsePage(q,[a,b]),q)).items).toHaveLength(2)
 })
 it('缺失、跨查询、跨来源、重复与乱序结果不能替代正常列表',async()=>{
  const q=query(),row=responseTask();q.limit=1
  for(const value of [null,{},responsePage(q,[row,row]),{...responsePage(q),query:{...object(q),end:new Date(Date.parse(q.end)-1000).toISOString()}},{...responsePage(q),query:{...object(q),limit:2}},responsePage(q,[{...row,kind:'diagnostics'}]),responsePage(q,[{...row,response_action:undefined}]),responsePage(q,[{...row,created_at:q.end}]),responsePage(q,[{...row,created_at:'2000-01-01T00:00:00Z'}])])await expect(readResponsePage(value,q)).rejects.toThrow()
  for(const field of ['sensor_id','device_id','target_ip','kind','state'] as const){const exact={...q,[field]:'other'};await expect(readResponsePage(responsePage(exact,[row]),exact)).rejects.toThrow()}
  const two={...q,limit:2};await expect(readResponsePage(responsePage(two,[row,row]),two)).rejects.toThrow()
  const page=responsePage(q,[row]);page.next_cursor=await token(q,{...row,id:'task_wrong'});await expect(readResponsePage(page,q)).rejects.toThrow()
  for(const invalid of ['bad','%%%','a'.repeat(513),btoa('{}'),btoa('null'),await token({...q,limit:2},row)]){page.next_cursor=invalid;await expect(readResponsePage(page,q)).rejects.toThrow()}
  const incoming={...q,cursor:await token({...q,limit:2},row)};await expect(readResponsePage(responsePage(incoming),incoming)).rejects.toThrow()
 })
 it('工程入口只查询响应目录，筛选、重置与空结果可操作',async()=>{
  request.mockImplementation(async(path:string)=>responsePage(fromPath(path)))
  const wrapper=mount(ResponseActionsView,{global:{plugins:[registerAnt]},attachTo:document.body});wrappers.push(wrapper);await flushPromises()
  await vi.waitFor(()=>expect(wrapper.text()).toContain('当前条件下没有响应动作'));expect(wrapper.get('h1').text()).toBe('响应动作');for(const [id,label] of [['response-kind','动作类型'],['response-state','执行状态']])expect((document.getElementById(id!) as HTMLInputElement).labels?.[0]?.textContent).toContain(label);expect(request.mock.calls[0]?.[0]).toContain('/response-actions?');expect(wrapper.text()).toContain('当前条件下没有响应动作')
  await wrapper.get('[aria-label="响应目标 IP"]').setValue('198.51.100.24');await click('查询');expect(fromPath(request.mock.lastCall![0]).target_ip).toBe('198.51.100.24');await vi.waitFor(()=>expect(wrapper.findAll('button').find(button=>button.text().replace(/\s/g,'')==='重置')?.attributes('disabled')).toBeUndefined())
  await click('重置');expect(fromPath(request.mock.lastCall![0]).target_ip).toBe('');await vi.waitFor(()=>expect(wrapper.text()).not.toContain('正在读取数据'))
  await wrapper.get('[aria-label="响应开始时间"]').setValue('2000-01-01T00:00:00');const before=request.mock.calls.length;await click('查询');expect(request).toHaveBeenCalledTimes(before);expect(wrapper.text()).toContain('窗口最多 31 天')
 })
 it('续页不重新计算时间，查询后回到第一页；失败保留可重试的页面边界',async()=>{
  let first:ResponseQuery|undefined
  request.mockImplementation(async(path:string)=>{const q=fromPath(path);first??=q;const items=Array.from({length:20},(_,i)=>responseTask('task_'+String(99-i)));items.forEach(row=>row.created_at=items[0]!.created_at);const page=responsePage(q,q.cursor?[]:items);page.next_cursor=q.cursor?'':await token(q,items.at(-1)!);return page})
  const wrapper=mount(TaskWorkspace,{props:{responseOnly:true},global:{plugins:[registerAnt]},attachTo:document.body});wrappers.push(wrapper);await vi.waitFor(()=>expect(wrapper.text()).toContain('task_99'));await click('下一页');const next=fromPath(request.mock.lastCall![0]);expect(next.start).toBe(first!.start);expect(next.end).toBe(first!.end);expect(next.cursor).not.toBe('');await vi.waitFor(()=>expect(wrapper.text()).toContain('当前条件下没有响应动作'));await click('上一页');await vi.waitFor(()=>expect(wrapper.text()).toContain('task_99'));expect(fromPath(request.mock.lastCall![0]).cursor).toBe('')
  request.mockRejectedValueOnce(new Error('目录读取失败'));await click('刷新任务');await vi.waitFor(()=>expect(wrapper.text()).toContain('当前显示上次成功读取的状态'));expect(wrapper.findAll('button').find(button=>button.text()==='下一页')?.attributes('disabled')).toBeDefined()
 })
 it('独立详情使用响应接口，其他任务不能混入；卸载后忽略迟到结果',async()=>{
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/response/actions',component:ResponseActionsView}]});await router.push('/response/actions?task=task_owned');await router.isReady()
  request.mockImplementation(async(path:string)=>path.includes('?')?responsePage(fromPath(path)):({...responseTask(),kind:'diagnostics'}))
  const wrapper=mount(ResponseActionsView,{global:{plugins:[registerAnt,router]},attachTo:document.body});wrappers.push(wrapper);await flushPromises();expect(request.mock.calls.some(call=>call[0]==='/response-actions/task_owned')).toBe(true);expect(document.body.textContent).toContain('任务详情未能完整返回')
  const late=deferred<unknown>();request.mockImplementation(()=>late.promise);await click('刷新任务');wrappers.pop();wrapper.unmount();late.resolve(responsePage(query()));await flushPromises();expect(document.querySelector('.ant-modal')).toBeNull()
 })
 it('未知联动提交保留原输入与键，设备目录变化仍可确认；确定拒绝清除尝试',async()=>{
  const row=responseTask(),binding={connector_id:'connector_owned',device_id:'device_owned',version:'protocol-fixture/1',config_sha256:'a'.repeat(64),status:'ready',observed_at:new Date().toISOString(),max_ttl_seconds:3600}
  request.mockImplementation(async(path:string)=>path.startsWith('/tasks')?{items:[row]}:{items:[{...sensor,last_seen:new Date().toISOString(),health:{...sensor.health,task_capabilities:['response.read','response.revoke'],response_connectors:[binding]}}]})
  const wrapper=mount(TaskWorkspace,{global:{plugins:[registerAnt]},attachTo:document.body});wrappers.push(wrapper);await flushPromises()
  request.mockImplementationOnce(async()=>({items:[{...sensor,last_seen:new Date().toISOString(),health:{...sensor.health,task_capabilities:['response.read'],response_connectors:[binding]}}]})).mockRejectedValueOnce(new Error('写入回执丢失'))
  await click('回读');const first=request.mock.lastCall!;expect(wrapper.text()).toContain('联动提交结果尚未确认')
  request.mockRejectedValueOnce(new ApiError(409,'changed','明确未受理'));await click('核对原联动提交');const second=request.mock.lastCall!;expect(second[0]).toBe(first[0]);expect(second[1].body).toEqual(first[1].body);expect(second[1].headers['Idempotency-Key']).toBe(first[1].headers['Idempotency-Key']);expect(wrapper.text()).not.toContain('联动提交结果尚未确认')
 })
 it('账号切换取消请求并清空筛选，不显示前一账号的迟到列表',async()=>{
  const late=deferred<unknown>();request.mockImplementationOnce(()=>late.promise).mockImplementation(async(path:string)=>responsePage(fromPath(path)))
  const wrapper=mount(TaskWorkspace,{props:{responseOnly:true},global:{plugins:[registerAnt]},attachTo:document.body});wrappers.push(wrapper);await wrapper.get('[aria-label="响应目标 IP"]').setValue('198.51.100.24');const first=request.mock.calls[0]!
  user.value={...principal,id:'other_admin'};await flushPromises();expect(first[1].signal.aborted).toBe(true);expect((wrapper.get('[aria-label="响应目标 IP"]').element as HTMLInputElement).value).toBe('');late.resolve(responsePage(fromPath(first[0]),[responseTask()]));await flushPromises();expect(wrapper.text()).not.toContain('task_owned')
 })
})
