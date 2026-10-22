import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {registerAnt} from '../packages/shared/src/ant'
import {emptyDeviceQuery,deviceQuery,readDevicePage,deviceState,usableDevice,readConfigCheck,type ResponseDevice,type DevicePage,type DeviceQuery} from '../packages/shared/src/responseDevices'
import {linkedResponseFilters} from '../packages/shared/src/responseCatalog'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import ResponseDevicesView from '../platform/src/views/ResponseDevicesView.vue'
import ResponseDeviceTable from '../packages/shared/src/components/ResponseDeviceTable.vue'
import ResponseDeviceDetail from '../packages/shared/src/components/ResponseDeviceDetail.vue'
import ResponseDialog from '../platform/src/features/sensors/ResponseDialog.vue'
import ResponseConfiguration from '../collector/src/features/network/ResponseConfiguration.vue'
import ResponseConfigCheckDialog from '../packages/shared/src/components/ResponseConfigCheckDialog.vue'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import {session} from '../platform/src/session'
import type {Principal} from '../packages/shared/src/types'
import {click,deferred,principal} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
vi.mock('../collector/src/session',()=>({session:{api:{request}}}))
const user=session.current as ShallowRef<Principal|null>,wrappers:VueWrapper[]=[],global={plugins:[registerAnt]}
function device():ResponseDevice{const at=new Date().toISOString();return {sensor_id:'sensor_hq',sensor_name:'总部探针',registration_id:'registration_hq',sensor_status:'online',last_seen:at,host_observed_at:at,observation:'fresh',task_supported:true,connector_id:'connector_hq',device_id:'device_hq',version:'fixture/1',status:'ready',observed_at:at,config_sha256:'a'.repeat(64),max_ttl_seconds:3600}}
function qFrom(path:string):DeviceQuery{return Object.fromEntries([...new URLSearchParams(path.split('?')[1])].map(([k,v])=>[k,k==='limit'?Number(v):v])) as unknown as DeviceQuery}
function page(q:DeviceQuery,items:ResponseDevice[]=[]):DevicePage{return {items,next_cursor:'',query:q,observed_at:new Date().toISOString()}}
async function cursor(q:DeviceQuery,v:ResponseDevice){return btoa(JSON.stringify({sensor_id:v.sensor_id,connector_id:v.connector_id,query:await goJSONDigest({sensor_id:q.sensor_id,device_id:q.device_id,status:q.status,cursor:'',limit:q.limit})})).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')}
async function view(){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/response/devices',component:ResponseDevicesView},{path:'/response/actions',component:TaskWorkspace}]});await router.push('/response/devices');await router.isReady();const wrapper=mount(ResponseDevicesView,{global:{plugins:[registerAnt,router]},attachTo:document.body});wrappers.push(wrapper);await vi.waitFor(()=>expect(wrapper.text()).not.toContain('正在读取数据'));await flushPromises();return {router,wrapper}}
beforeEach(()=>{vi.clearAllMocks();user.value=principal;request.mockImplementation(async(path:string)=>page(qFrom(path)))})
afterEach(()=>{for(const wrapper of wrappers.splice(0))wrapper.unmount();document.body.innerHTML='';vi.useRealTimers()})

describe('联动设备目录和配置核对',()=>{
 it('查询与分页同时绑定探针、设备、核验状态和页大小',async()=>{
  const q=emptyDeviceQuery();expect(deviceQuery(q)).toEqual(q)
  for(const change of [{sensor_id:'UPPER'},{device_id:'bad/id'},{status:'online'}])expect(()=>deviceQuery({...q,...change})).toThrow()
  const row=device();q.limit=1;const first=page(q,[row]);first.next_cursor=await cursor(q,row);expect((await readDevicePage(first,q)).items).toHaveLength(1)
  const next={...q,cursor:first.next_cursor},other={...row,sensor_id:'sensor_later'};expect((await readDevicePage(page(next,[other]),next)).items[0]?.sensor_id).toBe('sensor_later')
  for(const change of [{items:[row,row]},{query:{...q,limit:2}},{observed_at:'bad'},{next_cursor:'bad'},{next_cursor:await cursor({...q,limit:2},row)},{next_cursor:await cursor(q,{...row,sensor_id:'sensor_wrong'})}])await expect(readDevicePage({...first,...change},q)).rejects.toThrow()
  for(const change of [{sensor_id:'UPPER'},{device_id:'bad/id'},{registration_id:'bad/id'},{sensor_name:''},{version:'\n'},{config_sha256:'bad'},{max_ttl_seconds:0},{status:'unknown'},{sensor_status:'unknown'},{task_supported:null},{last_seen:'bad'},{host_observed_at:'bad'},{observed_at:'bad'},{observation:'pending'}])await expect(readDevicePage(page(q,[{...row,...change} as ResponseDevice]),q)).rejects.toThrow()
  for(const field of ['sensor_id','device_id','status'] as const){const exact={...q,[field]:'different'};await expect(readDevicePage(page(exact,[row]),exact)).rejects.toThrow()}
  await expect(readDevicePage(page(next,[row]),next)).rejects.toThrow();await expect(readDevicePage(page({...next,limit:2}),{...next,limit:2})).rejects.toThrow();await expect(readDevicePage(null,q)).rejects.toThrow()
 })
 it('未核验、不可用、离线、停用与过期不会误标为可提交',()=>{
  const row=device();expect(usableDevice(row)).toBe(true);expect(deviceState(row)).toBe('具备提交条件')
  for(const [change,label] of [[{sensor_status:'disabled'},'探针已停用'],[{sensor_status:'offline'},'探针离线或心跳过期'],[{observation:'pending'},'等待设备核验'],[{observation:'stale'},'设备观测已过期'],[{status:'unavailable'},'设备不可用'],[{status:'unverified'},'身份待核验'],[{task_supported:false},'执行能力不完整'],[{host_observed_at:new Date(Date.now()-36000).toISOString()},'探针观测已过期']] as const){const v={...row,...change};expect(usableDevice(v)).toBe(false);expect(deviceState(v)).toBe(label)}
  expect(deviceState(row,Date.now()+36000)).toBe('设备观测已过期')
 })
 it('目录空状态、筛选、重置、无效标识与单表布局可用',async()=>{
  const {wrapper}=await view();await vi.waitFor(()=>expect(wrapper.text()).toContain('当前条件下没有联动设备'));expect(wrapper.get('h1').text()).toBe('联动设备');expect(request.mock.calls[0]?.[0]).toContain('/response-connectors?')
  await wrapper.get('[aria-label="联动设备标识"]').setValue('device_hq');await click('查询');expect(qFrom(request.mock.lastCall![0]).device_id).toBe('device_hq');await vi.waitFor(()=>expect(wrapper.findAll('button').find(b=>b.text().replace(/\s/g,'')==='重置')?.attributes('disabled')).toBeUndefined());await click('重置');expect(qFrom(request.mock.lastCall![0]).device_id).toBe('');await vi.waitFor(()=>expect(wrapper.findAll('button').find(b=>b.text().replace(/\s/g,'')==='重置')?.attributes('disabled')).toBeUndefined())
  await wrapper.get('[aria-label="设备执行探针"]').setValue('UPPER');const count=request.mock.calls.length;await click('查询');await vi.waitFor(()=>expect(wrapper.text()).toContain('1–64 位'));expect(request).toHaveBeenCalledTimes(count)
 })
 it('查看与动作关联使用同一探针设备；失败保留旧目录但停止续页',async()=>{
  request.mockImplementation(async(path:string)=>page(qFrom(path),[device()]));const {wrapper,router}=await view();await vi.waitFor(()=>expect(wrapper.text()).toContain('device_hq'));expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1)
  wrapper.getComponent(ResponseDeviceTable).vm.$emit('view',device());await flushPromises();expect(document.body.textContent).toContain('配置 SHA-256');expect(wrapper.getComponent(ResponseDeviceDetail).props('device')!.device_id).toBe('device_hq')
  wrapper.getComponent(ResponseDeviceDetail).vm.$emit('close');request.mockRejectedValueOnce(new Error('连接中断'));await click('刷新设备');await vi.waitFor(()=>expect(wrapper.text()).toContain('当前显示上次成功读取的目录'));expect(wrapper.text()).toContain('device_hq');expect(wrapper.findAll('button').find(b=>b.text()==='下一页')?.attributes('disabled')).toBeDefined()
  wrapper.getComponent(ResponseDeviceTable).vm.$emit('actions',device());await vi.waitFor(()=>expect(router.currentRoute.value.fullPath).toBe('/response/actions?sensor_id=sensor_hq&device_id=device_hq'))
 })
 it('翻页、上一页与重查使用受控续页，空页不丢失回退入口',async()=>{
  request.mockImplementation(async(path:string)=>{const q=qFrom(path),rows=Array.from({length:20},(_,i)=>({...device(),connector_id:'connector_'+String(i).padStart(2,'0'),device_id:'device_'+i})),value=page(q,q.cursor?[]:rows);if(!q.cursor)value.next_cursor=await cursor(q,rows.at(-1)!);return value});const {wrapper}=await view();await vi.waitFor(()=>expect(wrapper.text()).toContain('device_19'));await click('下一页');expect(qFrom(request.mock.lastCall![0]).cursor).not.toBe('');await vi.waitFor(()=>expect(wrapper.text()).toContain('当前条件下没有联动设备'));await click('上一页');expect(qFrom(request.mock.lastCall![0]).cursor).toBe('');await vi.waitFor(()=>expect(wrapper.text()).toContain('device_19'))
 })
 it('所选配置摘要或注册变化阻止封禁，不能静默换设备',async()=>{
  const original=device();request.mockImplementation(async(path:string)=>page(qFrom(path),[original]));const {wrapper,router}=await view();await vi.waitFor(()=>expect(wrapper.text()).toContain('device_hq'))
  request.mockImplementationOnce(async(path:string)=>page(qFrom(path),[{...original,config_sha256:'b'.repeat(64)}]));wrapper.getComponent(ResponseDeviceTable).vm.$emit('respond',original);await flushPromises();await vi.waitFor(()=>expect(document.body.textContent).toContain('身份、配置或就绪状态已变化'));expect(new DOMWrapper(document.body).find('form[layout]').exists()).toBe(false)
  wrapper.getComponent(ResponseDialog).vm.$emit('close');await flushPromises();request.mockImplementationOnce(async(path:string)=>page(qFrom(path),[original]));wrapper.getComponent(ResponseDeviceTable).vm.$emit('respond',original);await vi.waitFor(()=>expect(document.querySelector('[aria-label="封禁目标 IP"]')).not.toBeNull());expect(wrapper.getComponent(ResponseDialog).props('binding')).toMatchObject({config_sha256:original.config_sha256});wrapper.getComponent(ResponseDialog).vm.$emit('submitted','task_'+'a'.repeat(32));await flushPromises();expect(router.currentRoute.value.query).toMatchObject({sensor_id:original.sensor_id,device_id:original.device_id,task:'task_'+'a'.repeat(32)})
 })
 it('身份切换和卸载取消请求，不显示旧租户迟到目录',async()=>{
  const wait=deferred<unknown>();request.mockImplementationOnce(()=>wait.promise);const {wrapper}=await view();const call=request.mock.calls[0]!;user.value={...principal,id:'other_admin'};await flushPromises();expect(call[1].signal.aborted).toBe(true);wait.resolve(page(qFrom(call[0]),[device()]));await flushPromises();expect(wrapper.text()).not.toContain('device_hq');wrapper.unmount()
 })
 it('配置核对严格校验模式、数量和时间，不把文件匹配当作设备认证',async()=>{
  const value={schema_version:'response.config-check.v1',state:'current',running_count:1,file_count:1,checked_at:new Date().toISOString()};expect(readConfigCheck(value).state).toBe('current')
  for(const change of [{state:'unknown'},{running_count:9},{file_count:0},{checked_at:'bad'},{schema_version:'v0'},{state:'not_configured'}])expect(()=>readConfigCheck({...value,...change})).toThrow()
  request.mockResolvedValueOnce(value);const wrapper=mount(ResponseConfiguration,{global,attachTo:document.body});wrappers.push(wrapper);await click('核对本地配置');expect(request.mock.lastCall![0]).toBe('/response-config-check');expect(document.body.textContent).toContain('文件与运行配置一致');expect(document.body.textContent).toContain('不证明 CA 或凭据有效')
  for(const state of ['restart_required','invalid','not_configured']){request.mockResolvedValueOnce({...value,state,running_count:state==='not_configured'?0:1,file_count:state==='not_configured'?0:1});wrapper.getComponent(ResponseConfigCheckDialog).vm.$emit('retry');await flushPromises();expect(wrapper.getComponent(ResponseConfigCheckDialog).props('result')!.state).toBe(state)}
  request.mockRejectedValueOnce(new Error('文件读取失败'));wrapper.getComponent(ResponseConfigCheckDialog).vm.$emit('retry');await flushPromises();expect(document.body.textContent).toContain('文件读取失败');wrapper.getComponent(ResponseConfigCheckDialog).vm.$emit('close');await flushPromises();expect(wrapper.getComponent(ResponseConfigCheckDialog).props('open')).toBe(false)
 })
 it('关联动作链接拒绝多值和无效标识；无效链接不会执行无范围查询',async()=>{
  expect(linkedResponseFilters({sensor_id:'sensor_hq',device_id:'device_hq'})).toMatchObject({sensor_id:'sensor_hq',device_id:'device_hq'})
  for(const value of [{sensor_id:['sensor_hq','other']},{device_id:null},{sensor_id:'UPPER'}])expect(()=>linkedResponseFilters(value)).toThrow()
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/response/actions',component:TaskWorkspace}]});await router.push('/response/actions?sensor_id=UPPER');await router.isReady();const wrapper=mount(TaskWorkspace,{props:{responseOnly:true},global:{plugins:[registerAnt,router]},attachTo:document.body});wrappers.push(wrapper);await flushPromises();expect(request).not.toHaveBeenCalled();await click('刷新任务');expect(request).not.toHaveBeenCalled();await router.push('/response/actions?sensor_id=sensor_hq&device_id=device_hq');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('sensor_id=sensor_hq');expect(request.mock.lastCall?.[0]).toContain('device_id=device_hq')
 })
})
