import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {message,Checkbox,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {ShallowRef} from 'vue'
import type {CaptureConfig,Principal,Sensor} from '../packages/shared/src/types'
import CaptureDialog from '../platform/src/features/sensors/CaptureDialog.vue'
import CaptureForm from '../packages/shared/src/components/CaptureForm.vue'
import CaptureResult from '../packages/shared/src/components/CaptureResult.vue'
import SensorDetail from '../platform/src/features/sensors/SensorDetail.vue'
import {session} from '../platform/src/session'
import {closedMessage,principal,sensor,click,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]}
const user=session.current as ShallowRef<Principal|null>
const settings={interfaces:['eth0'],threads:2,bpf_filter:'tcp port 80',promiscuous:false}
const capture:CaptureConfig={...settings,managed:true,status:'running',revision:4,applied_revision:4,applied_settings:{...settings},settings_sha256:'a'.repeat(64),config_sha256:'b'.repeat(64),observed_at:'2026-10-03T01:00:00Z'}
const iface={name:'eth0',index:1,mac:'02:00:00:00:00:01',mtu:1500,up:true,loopback:false,addresses:['192.0.2.1/24']}
const observed=():Sensor=>({...sensor,last_seen:new Date().toISOString(),active:true,status:'online',health:{...sensor.health,capture,network_interfaces:[iface],task_capabilities:['diagnostics','capture.configure']}})
beforeEach(()=>{user.value=principal;request.mockReset();request.mockResolvedValue({items:[observed()]});vi.spyOn(message,'success').mockImplementation(closedMessage)})
async function modal(target=observed()){const wrapper=mount(CaptureDialog,{props:{sensor:target},global,attachTo:document.body});await flushPromises();return wrapper}
async function submit(wrapper:Awaited<ReturnType<typeof modal>>){await wrapper.getComponent(CaptureForm).get('form').trigger('submit');await flushPromises()}

describe('平台采集配置',()=>{
 it('先读取设备实际观测，再绑定注册身份、期望修订及摘要下发；失败保留草稿和幂等键',async()=>{
  const wrapper=await modal();expect(request.mock.calls[0]?.[0]).toBe('/sensors');expect(document.body.textContent).toContain('配置经平台签名后下发')
  const form=wrapper.getComponent(CaptureForm);await form.get('input[aria-label="BPF 捕获过滤器"]').setValue('  tcp port 8088  ')
  request.mockRejectedValueOnce(new Error('暂时无法提交'));await submit(wrapper);expect(document.body.textContent).toContain('暂时无法提交')
  const first=request.mock.lastCall!,key=first[1].headers['Idempotency-Key'];expect(first[0]).toBe('/sensors/'+sensor.id+'/tasks');expect(first[1].body).toEqual({kind:'capture.configure',capture_configuration:{expected_revision:4,expected_config_sha256:'b'.repeat(64),expected_settings_sha256:'a'.repeat(64),settings:{...settings,bpf_filter:'tcp port 8088'}}})
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);form.vm.$emit('save',{...settings,bpf_filter:'tcp port 8088'});form.vm.$emit('save',{...settings,bpf_filter:'tcp port 8088'});await flushPromises();expect(request.mock.calls).toHaveLength(3);expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).toBe(key);expect(form.props('saving')).toBe(true)
  pending.resolve({id:'task_configuration'});await flushPromises();expect(wrapper.emitted('submitted')).toHaveLength(1);expect(message.success).toHaveBeenCalledWith('采集配置已受理，请在任务记录中核对设备回执')
 })
 it('草稿发生变化后使用独立幂等键，停止采集必须明确确认',async()=>{
  const wrapper=await modal(),form=wrapper.getComponent(CaptureForm)
  request.mockRejectedValueOnce('offline');await submit(wrapper);expect(document.body.textContent).toContain('采集配置任务提交失败');const previous=request.mock.lastCall?.[1].headers['Idempotency-Key']
  await form.getComponent(Select).setValue([],'value');await submit(wrapper);expect(request.mock.calls).toHaveLength(2);expect(document.body.textContent).toContain('下发停止采集')
  await form.findAllComponents(Checkbox).at(-1)!.setValue(true,'checked');request.mockResolvedValueOnce({id:'task_stop'});await submit(wrapper)
  expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).not.toBe(previous);expect(request.mock.lastCall?.[1].body.capture_configuration.settings.interfaces).toEqual([])
 })
 it('加载失败可重试，初始停止状态的空配置摘要仍绑定设备参数摘要',async()=>{
  request.mockRejectedValueOnce('offline');const wrapper=await modal();expect(document.body.textContent).toContain('无法读取探针采集配置')
  const row=observed();row.health.capture={...capture,interfaces:[],status:'stopped',config_sha256:undefined,applied_settings:{...settings,interfaces:[]}};request.mockResolvedValueOnce({items:[row]});await click('重试');expect(wrapper.findComponent(CaptureForm).exists()).toBe(true)
  request.mockResolvedValueOnce({id:'task_initial'});await submit(wrapper);expect(request.mock.lastCall?.[1].body.capture_configuration.expected_config_sha256).toBe('')
 })
 it('离线、换证、旧观测和不完整接口信息均禁止下发',async()=>{
  for(const change of [(r:Sensor)=>{r.status='offline'},(r:Sensor)=>{r.registration_id='changed'},(r:Sensor)=>{r.last_seen='invalid'},(r:Sensor)=>{r.last_seen=new Date(Date.now()-36000).toISOString()},(r:Sensor)=>{r.last_seen=new Date(Date.now()+120000).toISOString()},(r:Sensor)=>{r.health.capture={...capture,settings_sha256:undefined}},(r:Sensor)=>{r.health.network_interfaces=undefined},(r:Sensor)=>{r.health.capture={...capture,status:'pending'}},(r:Sensor)=>{r.health.capture={...capture,status:'starting'}},(r:Sensor)=>{r.health.capture=undefined},(r:Sensor)=>{r.health.task_capabilities=[]},(r:Sensor)=>{r.active=false}]){
   const row=observed();change(row);request.mockResolvedValueOnce({items:[row]});const wrapper=await modal();expect(wrapper.findComponent(CaptureForm).exists()).toBe(false);expect(document.body.textContent).toContain('尚未完整观测');wrapper.unmount();document.body.replaceChildren()
  }
 })
 it('切换目标或关闭页面取消旧请求，迟到响应不覆盖当前目标或宣布受理',async()=>{
  const first=deferred<{items:Sensor[]}>();request.mockImplementationOnce(()=>first.promise);const wrapper=mount(CaptureDialog,{props:{sensor:observed()},global,attachTo:document.body});await flushPromises();const oldSignal=request.mock.lastCall?.[1].signal as AbortSignal
  const other={...observed(),id:'sensor_other',registration_id:'registration_other'};request.mockResolvedValueOnce({items:[other]});await wrapper.setProps({sensor:other});await flushPromises();expect(oldSignal.aborted).toBe(true);first.resolve({items:[observed()]});await flushPromises();expect(wrapper.findComponent(CaptureForm).exists()).toBe(true)
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await submit(wrapper);const signal=request.mock.lastCall?.[1].signal as AbortSignal;await wrapper.setProps({sensor:null});expect(signal.aborted).toBe(true);pending.resolve({id:'late_task'});await flushPromises();expect(wrapper.emitted('submitted')).toBeUndefined();expect(message.success).not.toHaveBeenCalled()
  const loading=deferred<{items:Sensor[]}>();request.mockImplementationOnce(()=>loading.promise);await wrapper.setProps({sensor:observed()});await flushPromises();const closing=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(closing.aborted).toBe(true);loading.reject(new Error('late_failure'));await flushPromises()
 })
 it('只读账号不能读取或提交管理配置，未选目标不发请求',async()=>{
  user.value={...principal,role:'viewer'} as Principal;const wrapper=await modal();expect(document.body.textContent).toContain('当前账号没有采集配置权限');expect(request).not.toHaveBeenCalled();await wrapper.setProps({sensor:null});expect(request).not.toHaveBeenCalled()
 })
 it('探针详情提供独立配置入口和本机接口信息，只读角色保留状态查看',async()=>{
  const wrapper=mount(SensorDetail,{props:{sensor:observed()},global,attachTo:document.body});expect(document.body.textContent).toContain(iface.mac);await click('采集配置');expect(wrapper.emitted('configure')?.[0]?.[0]).toMatchObject({id:sensor.id})
  await wrapper.setProps({sensor:{...observed(),status:'offline'}});const buttons=[...document.body.querySelectorAll<HTMLButtonElement>('button')];expect(buttons.find(b=>b.textContent==='采集配置')?.disabled).toBe(true)
  user.value={...principal,role:'viewer'};await flushPromises();expect([...document.body.querySelectorAll('button')].some(b=>b.textContent==='运行诊断')).toBe(false)
 })
})

describe('采集任务回读',()=>{
 it('分别展示期望与生效网卡、修订和原生配置摘要，缺测不补零',async()=>{
  const wrapper=mount(CaptureResult,{props:{result:{...capture}},global});expect(wrapper.text()).toContain('采集中');expect(wrapper.text()).toContain('4 / 4');expect(wrapper.text()).toContain('eth0');expect(wrapper.text()).toContain('b'.repeat(64));expect(wrapper.text()).toContain('执行时采集状态');expect(wrapper.text()).toContain('回执观测时间');expect(wrapper.text()).toContain('当前采集状态请在采集配置中核对');expect(wrapper.text()).not.toContain('实际采集状态')
  await wrapper.setProps({result:{status:'unrecognized',revision:'4',applied_settings:{},config_sha256:'bad'}});expect(wrapper.text()).toContain('状态无法识别');expect(wrapper.text()).toContain('尚未观测');expect(wrapper.text()).toContain('未获取')
  await wrapper.setProps({result:{status:'stopped',interfaces:[],applied_settings:{interfaces:[]}}});expect(wrapper.text()).toContain('已停止');expect(wrapper.text()).toContain('未采集')
  await wrapper.setProps({result:{interfaces:[null]}});expect(wrapper.text()).toContain('尚未观测')
 })
})
