import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {message,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiClient} from '../packages/shared/src/api'
import ReplayWorkspace from '../packages/shared/src/components/ReplayWorkspace.vue'
import ReplayResult from '../packages/shared/src/components/ReplayResult.vue'
import TaskTable from '../packages/shared/src/components/TaskTable.vue'
import RuleEditor from '../packages/shared/src/components/RuleEditor.vue'
import {closedMessage,sample,sensor,task,rulePackage,rules,click,button,writeRule,deferred} from './fixtures'
const request=vi.fn(),api=new ApiClient('/test')
api.request=request
const global={plugins:[registerAnt]}
const samples={items:[sample],available:true,registered_rules_available:true}
beforeEach(()=>{request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?samples:path==='/tasks'?{items:[]}:path==='/sensors'?{items:[sensor]}:path==='/rule-packages'?{items:[rulePackage]}:{id:task.id}));vi.spyOn(message,'success').mockImplementation(closedMessage);vi.spyOn(message,'error').mockImplementation(closedMessage)})
async function mountWorkspace(local=false,view:'samples'|'tasks'='samples'){const wrapper=mount(ReplayWorkspace,{props:{api,local,view},global,attachTo:document.body});await flushPromises();return wrapper}
async function file(value:File){const element=document.body.querySelector<HTMLInputElement>('#replay-file')!;Object.defineProperty(element,'files',{value:[value],configurable:true});element.dispatchEvent(new Event('change',{bubbles:true}));await flushPromises()}

describe('重放样本导入',()=>{
 it('未配置和无数据提供准确提示，失败可恢复',async()=>{
  request.mockResolvedValue({items:[],available:false});const wrapper=await mountWorkspace();expect(wrapper.text()).toContain('平台样本存储未配置');expect(button('导入样本').disabled).toBe(true)
  request.mockRejectedValueOnce(new Error('样本读取超时')).mockRejectedValueOnce('offline');await click('刷新');expect(wrapper.text()).toContain('样本读取超时');request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?{...samples,items:[]}: {items:[]}));await click('重试');expect(wrapper.text()).toContain('暂无重放样本')
 })
 it('先校验文件边界，失败保留文件，成功关闭弹窗并更新列表',async()=>{
  const wrapper=await mountWorkspace(true);await click('导入样本');await click('上传样本');expect(document.body.textContent).toContain('请选择 PCAP')
  await file(new File(['tiny'],'small.pcap'));await click('上传样本');expect(document.body.textContent).toContain('24 字节')
  const large=new File([],'too-large.pcap');Object.defineProperty(large,'size',{value:100*1024*1024+1});await file(large);await click('上传样本');expect(request.mock.calls.some(call=>call[1]?.method==='POST')).toBe(false)
  const valid=new File([new Uint8Array(24)],'valid.pcap');await file(valid);request.mockRejectedValueOnce(new Error('上传受阻'));await click('上传样本');expect(document.body.textContent).toContain('上传受阻');expect(document.body.textContent).toContain('valid.pcap')
  await click('上传样本');await vi.waitFor(()=>expect(document.body.querySelector('#replay-file')).toBeNull());expect(message.success).toHaveBeenCalled();expect(request.mock.calls.find(call=>call[1]?.file===valid)?.[1].signal).toBeInstanceOf(AbortSignal)
  await click('导入样本');await click('取消');expect(wrapper.text()).toContain(sample.name)
 })
 it('上传中阻止重复请求，离开页面终止请求且不显示迟到成功',async()=>{
  const wrapper=await mountWorkspace();await click('导入样本');await file(new File([new Uint8Array(24)],'valid.pcap'));const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);const action=button('上传样本');action.click();action.click();await flushPromises();expect(request.mock.calls.filter(call=>call[1]?.method==='POST')).toHaveLength(1)
  const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve(sample);await flushPromises();expect(message.success).not.toHaveBeenCalled()
 })
})

describe('重放任务提交',()=>{
 it('本地规则基础检查和失败重试使用同一任务幂等键',async()=>{
  const wrapper=await mountWorkspace(true);await click('重放测试');await click('执行重放');expect(document.body.textContent).toContain('请输入用于本次重放的规则');const editor=wrapper.getComponent(RuleEditor)
  await writeRule(editor,'drop tcp any any -> any any (sid:1;)');await click('执行重放');expect(document.body.textContent).toContain('第 1 行')
  await writeRule(editor,rules);request.mockRejectedValueOnce(new Error('任务提交超时'));await click('执行重放');expect(document.body.textContent).toContain('任务提交超时');const key=request.mock.lastCall?.[1].headers['Idempotency-Key']
  const pending=deferred<{id:string}>();request.mockImplementationOnce(()=>pending.promise);const action=button('执行重放');action.click();action.click();await flushPromises();expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).toBe(key);expect(request.mock.calls.filter(call=>call[0]==='/replay/tasks')).toHaveLength(2)
  pending.resolve({id:task.id});await flushPromises();expect(document.body.textContent).toContain('重放任务已受理');expect(button('执行重放').disabled).toBe(true);await click('查看任务记录');expect(wrapper.emitted('tasks')).toHaveLength(1)
 })
 it('平台选择探针和不可变规则修订，登记快照受探针能力约束',async()=>{
  const wrapper=await mountWorkspace();await click('重放测试');await click('执行重放');expect(document.body.textContent).toContain('请选择具有离线重放能力')
  const selects=wrapper.findAllComponents(Select);await selects[0]!.setValue(sensor.id,'value');await click('执行重放');expect(document.body.textContent).toContain('请选择规则包修订');await selects[1]!.setValue(rulePackage.id,'value')
  request.mockRejectedValueOnce('offline');await click('执行重放');expect(document.body.textContent).toContain('重放任务提交失败');await click('执行重放');expect(request.mock.calls.find(call=>call[0]===`/sensors/${sensor.id}/tasks`)?.[1].body).toEqual({kind:'rules.replay',sample_id:sample.id,rule_mode:'package',package_id:rulePackage.id,revision:rulePackage.revision})
  ;(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();await click('重放测试');await wrapper.findAllComponents(Select)[0]!.setValue(sensor.id,'value');const radios=document.body.querySelectorAll<HTMLInputElement>('.ant-modal input[type=radio]');radios[1]!.click();await flushPromises();await click('执行重放');expect(request.mock.calls.filter(call=>call[1]?.body?.rule_mode==='registered')).toHaveLength(1)
 })
 it('执行选项失败和页面离开不会写入旧数据或重复提交任务',async()=>{
  const wrapper=await mountWorkspace();const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await click('重放测试');const signal=request.mock.calls.findLast(call=>call[0]==='/sensors')?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve({items:[sensor]});await flushPromises();expect(message.success).not.toHaveBeenCalled()
 })
 it('已登记规则可直接重放，能力缺失时不能选择登记快照',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?{...samples,registered_rules_available:false}: {items:[]}));const wrapper=await mountWorkspace(true);await click('重放测试');const registered=document.body.querySelector<HTMLInputElement>('input[value=registered]');expect(registered?.disabled).toBe(true)
  wrapper.unmount();request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?samples:path==='/tasks'?{items:[]}:{id:task.id}));const next=await mountWorkspace(true);await click('重放测试');document.body.querySelector<HTMLInputElement>('input[value=registered]')!.click();await flushPromises();await click('执行重放');expect(request.mock.calls.findLast(call=>call[0]==='/replay/tasks')?.[1].body).toMatchObject({rule_mode:'registered',rules:''});next.unmount()
 })
})

describe('执行回执与自动更新',()=>{
 it('平台任务视图只显示重放任务，本地任务视图包含诊断',async()=>{
  request.mockResolvedValue({items:[task,{...task,id:'diagnostic',kind:'diagnostics',state:'succeeded'}],available:true});const wrapper=await mountWorkspace(false,'tasks');expect(wrapper.text()).toContain('PCAP 重放');expect(wrapper.text()).not.toContain('运行诊断');await wrapper.setProps({local:true});expect(wrapper.text()).toContain('运行诊断');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  request.mockRejectedValue(new Error('回执连接受阻'));await click('刷新任务');expect(wrapper.text()).toContain('上次成功读取的状态');wrapper.unmount()
 })
 it('刷新替换旧请求，错误退避三次后停止并允许手动恢复',async()=>{
  vi.useFakeTimers();request.mockRejectedValue('offline');const wrapper=await mountWorkspace(false,'tasks');expect(wrapper.text()).toContain('任务状态读取失败');await vi.advanceTimersByTimeAsync(5000);await flushPromises();await vi.advanceTimersByTimeAsync(10000);await flushPromises();const count=request.mock.calls.length;await vi.advanceTimersByTimeAsync(20000);expect(request.mock.calls).toHaveLength(count)
  request.mockImplementation((path:string)=>Promise.resolve(path==='/replay/samples'?samples:{items:[{...task,state:'succeeded'}]}));await click('重试');expect(wrapper.text()).toContain('执行成功');const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true)
 })
 it('回执显示规则命中、MAC、捕获时间和限制，缺测不显示零值结论',async()=>{
  const wrapper=mount(ReplayResult,{props:{local:true,result:{replay:'completed',match_status:'matched',packets_processed:20,alert_count:1,duration_ms:50,rule_mode:'registered',sample_metadata:{first_packet_at:'2026-10-01T00:00:00Z',last_packet_at:null,truncated_packets:0,link_type:1,mac_addresses:['02:00:00:00:00:01']},alerts:[{signature_id:1,rev:1,signature:'test',src_ip:'192.0.2.1',src_port:80,dest_ip:'192.0.2.2',dest_port:5000,pcap_cnt:5,timestamp:'2026-10-01T00:00:00Z'}]}},global});expect(wrapper.text()).toContain('检测到规则命中');expect(wrapper.text()).toContain('登记规则快照');expect(wrapper.text()).toContain('02:00:00:00:00:01');expect(wrapper.text()).toContain('未获取')
  await wrapper.setProps({result:{replay:'completed',match_status:'unmatched',rule_mode:'package',alerts:'invalid'}});expect(wrapper.text()).toContain('未检测到规则命中');expect(wrapper.text()).toContain('本次输入规则');await wrapper.setProps({local:false,result:{replay:'failed',reason:'样本摘要不一致',rule_mode:'package',revision:4,sample_metadata:{},alerts:[]}});expect(wrapper.text()).toContain('样本摘要不一致');expect(wrapper.text()).toContain('指定规则包')
 })
 it('握手结果区分完整观测、缺测和资源限制，旧回执不补推结论',async()=>{
  const result={replay:'completed',match_status:'unmatched',sample_metadata:{truncated_packets:0,tcp_handshake:{assessed_flows:2,complete_handshakes:1,incomplete_flows:1,reused_tuples:0,skipped_packets:3,limited:true,limit_reasons:['flow_limit','decode_error','unknown'],checksum_validation:'not_checked'},mac_addresses:[],mac_addresses_limited:true}}
  const wrapper=mount(ReplayResult,{props:{result},global});expect(wrapper.text()).toContain('已观察 1 组完整三次握手');expect(wrapper.text()).toContain('1 个流缺少完整握手');expect(wrapper.text()).toContain('32,768');expect(wrapper.text()).toContain('跳过 3 帧');expect(wrapper.text()).toContain('其他观测限制');expect(wrapper.text()).toContain('不证明载荷完整或攻击成功');expect(wrapper.text()).toContain('前 32 个 MAC 地址')
  await wrapper.setProps({result:{...result,sample_metadata:{tcp_handshake:{...result.sample_metadata.tcp_handshake,assessed_flows:0,limited:false}}}});expect(wrapper.text()).toContain('未观察到可评估的 TCP 流');expect(wrapper.text()).not.toContain('观测限制：')
  await wrapper.setProps({result:{...result,sample_metadata:{truncated_packets:0}}});expect(wrapper.text()).toContain('TCP 握手尚未评估');expect(wrapper.text()).not.toContain('完整三次握手')
 })
 it('任务取消要求尚未投递，详情自动跟随回执并说明待核实状态',async()=>{
  const wrapper=mount(TaskTable,{props:{items:[task],cancellable:true},global,attachTo:document.body});await click('取消');await click('确定');expect(wrapper.emitted('cancel')?.[0]?.[0]).toEqual(task);await click('查看');expect(document.body.textContent).toContain('等待设备回执')
  await wrapper.setProps({items:[{...task,state:'unknown',delivery_count:1,receipt:{state:'unknown',code:'execution_interrupted',result:{}}}]});expect(document.body.textContent).toContain('执行结果待核实');expect(wrapper.findAll('button').some(value=>value.text()==='取消')).toBe(false)
  await wrapper.setProps({local:true,items:[{...task,kind:'rules.validate',state:'succeeded',origin:'local',acknowledged:true,receipt:{state:'succeeded',result:{syntax:'passed',replay:'not_run'}}}]});expect(wrapper.text()).toContain('本地任务');expect(document.body.textContent).toContain('不授予发布资格');expect(document.body.textContent).toContain('独立正、反样本验证');expect(document.body.textContent).not.toContain('样本回放尚未完成')
  await wrapper.setProps({items:[]});expect(document.body.textContent).not.toContain('不授予发布资格')
 })
})
