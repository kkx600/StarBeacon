import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {message} from 'ant-design-vue'
import type {ShallowRef} from 'vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal,Sensor,SensorTask} from '../packages/shared/src/types'
import {readyConnector,type ResponseConnector} from '../packages/shared/src/response'
import ResponseDialog from '../platform/src/features/sensors/ResponseDialog.vue'
import ResponseConnectors from '../packages/shared/src/components/ResponseConnectors.vue'
import TaskTable from '../packages/shared/src/components/TaskTable.vue'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import SensorDetail from '../platform/src/features/sensors/SensorDetail.vue'
import {session} from '../platform/src/session'
import {ApiError} from '../packages/shared/src/api'
import {closedMessage,principal,sensor,click,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]},user=session.current as ShallowRef<Principal|null>
const connector=():ResponseConnector=>({connector_id:'connector_test',device_id:'device_test',version:'protocol-fixture/1',config_sha256:'a'.repeat(64),status:'ready',observed_at:new Date().toISOString(),max_ttl_seconds:3600})
const observed=():Sensor=>({...sensor,last_seen:new Date().toISOString(),active:true,status:'online',health:{...sensor.health,task_capabilities:['response.block','response.read','response.revoke'],response_connectors:[connector()]}})
const taskID='task_'+'a'.repeat(32)
const task=():SensorTask=>({id:taskID,sensor_id:sensor.id,kind:'response.block',state:'unknown',created_by:principal.id,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+60000).toISOString(),delivery_count:1,updated_at:new Date().toISOString(),receipt:{},response_action:{schema_version:'response.action.v1',connector_id:'connector_test',config_sha256:'a'.repeat(64),device_id:'device_test',lease_id:taskID,owner_sha256:'b'.repeat(64),target_ip:'198.51.100.10',requested_at:new Date().toISOString(),expires_at:new Date(Date.now()+300000).toISOString(),reason:'明确人工授权'}})
beforeEach(()=>{user.value=principal;request.mockReset();request.mockResolvedValue({items:[observed()]});vi.spyOn(message,'success').mockImplementation(closedMessage);vi.spyOn(message,'error').mockImplementation(closedMessage)})
async function modal(){const wrapper=mount(ResponseDialog,{props:{sensor:observed()},global,attachTo:document.body});await flushPromises();return wrapper}
const dialogDOM=()=>new DOMWrapper(document.body)
async function fill(_wrapper:Awaited<ReturnType<typeof modal>>){await dialogDOM().get('input[aria-label="封禁目标 IP"]').setValue('198.51.100.10');await dialogDOM().get('textarea[aria-label="联动操作依据"]').setValue('异常通信人工确认');await dialogDOM().get('input[type="checkbox"]').setValue(true)}
async function submit(_wrapper:Awaited<ReturnType<typeof modal>>){await dialogDOM().get('form').trigger('submit');await flushPromises()}
describe('采集器 HTTP 联动',()=>{
 it('设备就绪检查包括标识、摘要、时间和原生最长 TTL',()=>{
  expect(readyConnector(connector())).toBe(true)
  for(const change of [(v:ResponseConnector)=>v.status='unverified',(v:ResponseConnector)=>v.connector_id='invalid/id',(v:ResponseConnector)=>v.device_id='UPPER',(v:ResponseConnector)=>v.config_sha256='bad',(v:ResponseConnector)=>v.observed_at='invalid',(v:ResponseConnector)=>v.observed_at=new Date(Date.now()-36000).toISOString(),(v:ResponseConnector)=>v.observed_at=new Date(Date.now()+31000).toISOString(),(v:ResponseConnector)=>v.max_ttl_seconds=29,(v:ResponseConnector)=>v.max_ttl_seconds=3601,(v:ResponseConnector)=>v.max_ttl_seconds=30.5]){const value=connector();change(value);expect(readyConnector(value)).toBe(false)}
 })
 it('明确确认后绑定设备配置提交，双击只提交一次，受理文案不声称流量被阻断',async()=>{
  const wrapper=await modal();await submit(wrapper);expect(request).toHaveBeenCalledTimes(1);expect(document.body.textContent).toContain('并确认提交')
  await fill(wrapper);const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise)
  dialogDOM().get('form').trigger('submit');dialogDOM().get('form').trigger('submit');await flushPromises();expect(request).toHaveBeenCalledTimes(2)
  const call=request.mock.lastCall!;expect(call[0]).toBe(`/sensors/${sensor.id}/response-tasks`);expect(call[1].body).toEqual({kind:'response.block',connector_id:'connector_test',config_sha256:'a'.repeat(64),target_ip:'198.51.100.10',ttl_seconds:300,reason:'异常通信人工确认'});expect(call[1].headers['Idempotency-Key']).toMatch(/^[a-z0-9-]{36}$/)
  pending.resolve({id:taskID});await flushPromises();expect(wrapper.emitted('submitted')).toHaveLength(1);expect(message.success).toHaveBeenCalledWith('联动任务已受理，请在任务记录中核对设备配置状态')
 })
 it('未知提交锁定输入与原键，完整回执确认后才能结束',async()=>{
  const wrapper=await modal();await fill(wrapper);request.mockRejectedValueOnce(new Error('网络中断'));await submit(wrapper)
  const original=request.mock.lastCall!;expect(document.body.textContent).toContain('核对原提交');expect(dialogDOM().get('input[aria-label="封禁目标 IP"]').attributes('disabled')).toBeDefined()
  request.mockResolvedValueOnce({id:'not-a-task'});await submit(wrapper);expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).toBe(original[1].headers['Idempotency-Key']);expect(wrapper.emitted('submitted')).toBeUndefined()
  request.mockResolvedValueOnce({id:taskID});await submit(wrapper);expect(request.mock.lastCall?.[1].body).toEqual(original[1].body);expect(wrapper.emitted('submitted')).toHaveLength(1)
 })
 it('确定拒绝允许修正输入；未知请求不会因设备观测过期换键或延长 TTL',async()=>{
  const wrapper=await modal();await fill(wrapper);request.mockRejectedValueOnce(new ApiError(400,'invalid_response_request','目标不在允许范围'));await submit(wrapper);const key=request.mock.lastCall?.[1].headers['Idempotency-Key']
  expect(dialogDOM().get('input[aria-label="封禁目标 IP"]').attributes('disabled')).toBeUndefined();await dialogDOM().get('input[aria-label="封禁目标 IP"]').setValue('198.51.100.11');request.mockRejectedValueOnce('offline');await submit(wrapper);expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).not.toBe(key)
  const frozen=request.mock.lastCall!;request.mockResolvedValueOnce({id:taskID});await submit(wrapper);expect(request.mock.lastCall?.[1].body).toEqual(frozen[1].body)
 })
 it('离线、换证、超时及能力缺失阻止提交；只读账号没有操作',async()=>{
  for(const change of [(v:Sensor)=>v.active=false,(v:Sensor)=>v.status='offline',(v:Sensor)=>v.registration_id='replacement',(v:Sensor)=>v.last_seen='invalid',(v:Sensor)=>v.last_seen=new Date(Date.now()-36000).toISOString(),(v:Sensor)=>v.last_seen=new Date(Date.now()+31000).toISOString(),(v:Sensor)=>v.health.task_capabilities=[],(v:Sensor)=>v.health.response_connectors=[]]){const row=observed();change(row);request.mockResolvedValueOnce({items:[row]});const wrapper=await modal();expect(dialogDOM().find('form').exists()).toBe(false);expect(document.body.textContent).toMatch(/尚未就绪|未就绪|就绪的联动/);wrapper.unmount()}
  user.value={...principal,role:'viewer'};const wrapper=await modal();expect(dialogDOM().find('form').exists()).toBe(false);wrapper.unmount()
 })
 it('切换身份和关闭会取消请求，迟到材料不显示成功',async()=>{
  const wait=deferred<unknown>();request.mockImplementationOnce(()=>wait.promise);const wrapper=await modal();const signal=request.mock.lastCall?.[1].signal as AbortSignal
  await wrapper.setProps({sensor:null});expect(signal.aborted).toBe(true);wait.resolve({items:[observed()]});await flushPromises();expect(wrapper.emitted('submitted')).toBeUndefined();wrapper.unmount()
  request.mockResolvedValueOnce({items:[observed()]});const second=await modal();await fill(second);const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await submit(second);const submitSignal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,id:'another_admin'};await flushPromises();expect(submitSignal.aborted).toBe(true);pending.resolve({id:taskID});await flushPromises();expect(second.emitted('submitted')).toBeUndefined()
 })
 it('目录空状态与健康状态明确，探针详情提供统一联动入口',async()=>{
  const wrapper=mount(ResponseConnectors,{props:{items:[]},global});expect(wrapper.text()).toContain('尚未登记联动设备');await wrapper.setProps({items:[connector()]});expect(wrapper.text()).toContain('设备已就绪');expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1)
  const detail=mount(SensorDetail,{props:{sensor:observed()},global,attachTo:document.body});await click('限时封禁');expect(detail.emitted('respond')?.[0]?.[0]).toMatchObject({id:sensor.id})
 })
 it('联动设备观测过期后不继续显示就绪，异常版本不可使用',async()=>{
  vi.useFakeTimers();const value=connector();const wrapper=mount(ResponseConnectors,{props:{items:[value]},global});expect(wrapper.text()).toContain('设备已就绪');vi.setSystemTime(new Date(Date.now()+36000));await vi.advanceTimersByTimeAsync(5000);expect(wrapper.text()).toContain('观测已过期');wrapper.unmount()
  for(const version of ['', 'version\n',' '.repeat(66)]){expect(readyConnector({...connector(),version})).toBe(false)}
 })
 it('任务回读与解除使用原租约，未知任务不显示解除成功',async()=>{
  const value=task(),wrapper=mount(TaskTable,{props:{items:[value],responseable:true},global,attachTo:document.body});await click('回读');expect(wrapper.emitted('response')?.[0]).toEqual([value,'response.read']);await click('查看');expect(document.body.textContent).toContain('封禁到期时间');expect(document.body.textContent).toContain('状态待核对');expect(document.body.textContent).toContain('尚未观测')
  await wrapper.setProps({responseable:false});expect(wrapper.text()).not.toContain('回读')
 })
 it('原提交确认沿用冻结输入，新操作核对当前设备配置',async()=>{
  const value=task();request.mockResolvedValueOnce({items:[value]});const wrapper=mount(TaskWorkspace,{global,attachTo:document.body});await flushPromises()
  request.mockResolvedValueOnce({items:[observed()]}).mockRejectedValueOnce(new Error('请求超时'));await click('回读');const first=request.mock.lastCall!;expect(first[1].body.original_task_id).toBe(value.id);expect(first[1].body.target_ip).toBeUndefined()
  request.mockResolvedValueOnce({id:taskID}).mockResolvedValueOnce({items:[value]});await click('回读');const mutation=request.mock.calls.filter(call=>call[0].endsWith('/response-tasks'));expect(mutation).toHaveLength(2);expect(mutation[1]?.[1].headers['Idempotency-Key']).toBe(first[1].headers['Idempotency-Key'])
  const changed=observed();changed.health.response_connectors![0]!.config_sha256='c'.repeat(64);request.mockResolvedValueOnce({items:[changed]});await click('回读');expect(request.mock.calls.filter(call=>call[0].endsWith('/response-tasks'))).toHaveLength(2);expect(message.error).toHaveBeenCalledWith('执行采集器或原设备配置尚未就绪，请刷新核对。');wrapper.unmount()
 })
})
