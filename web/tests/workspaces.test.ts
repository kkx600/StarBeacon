import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {type Component,type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Alert,HostHealth,Principal} from '../packages/shared/src/types'
import SensorsWorkspace from '../platform/src/features/sensors/SensorsWorkspace.vue'
import SensorDetail from '../platform/src/features/sensors/SensorDetail.vue'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import InventoryWorkspace from '../platform/src/features/inventory/InventoryWorkspace.vue'
import AuditWorkspace from '../platform/src/features/operations/AuditWorkspace.vue'
import OperationsWorkspace from '../platform/src/features/operations/OperationsWorkspace.vue'
import AlertsWorkspace from '../platform/src/features/alerts/AlertsWorkspace.vue'
import AlertFilters from '../platform/src/features/alerts/AlertFilters.vue'
import AdvancedFilter from '../platform/src/features/alerts/AdvancedFilter.vue'
import AlertDetail from '../platform/src/features/alerts/AlertDetail.vue'
import AlertTable from '../platform/src/features/alerts/AlertTable.vue'
import CollectorWorkspace from '../collector/src/features/network/CollectorWorkspace.vue'
import CaptureForm from '../packages/shared/src/components/CaptureForm.vue'
import InterfaceTable from '../collector/src/features/network/InterfaceTable.vue'
import HealthSummary from '../collector/src/features/network/HealthSummary.vue'
import DetectionQualityDialog from '../packages/shared/src/components/DetectionQualityDialog.vue'
import {session} from '../platform/src/session'
import {closedMessage,principal,sensor,task,click,button,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
vi.mock('../collector/src/session',()=>({session:{api:{request},get current(){return user}}}))
const global={plugins:[registerAnt]},user=session.current as ShallowRef<Principal|null>
const alert:Alert={event_id:'event_1',tenant_id:principal.tenant_id,sensor_id:sensor.id,'@timestamp':'2026-10-02T00:00:00Z',observed_at:'2026-10-02T00:00:00.003Z',received_at:'2026-10-02T00:00:00.006Z',source_offset:'9223372036854775800',sequence:'1',raw_sha256:'c'.repeat(64),source:{ip:'192.0.2.1',mac:'02:00:00:00:00:01'},destination:{ip:'192.0.2.2'},network:{transport:'tcp',protocol:'http'},rule:{id:'9900001',name:'API 命中'},http:{method:'GET',path:'/api'},suricata:{flow_id:'18446744073709551614'},severity:'high',event:{kind:'alert',original:JSON.stringify({payload:btoa('GET /api')})},evidence_status:'unavailable'}
const iface={name:'eth0',index:1,mac:'02:00:00:00:00:01',mtu:1500,up:true,loopback:false,addresses:['192.0.2.1/24','2001:db8::1/64']}
const health:HostHealth={version:'test',hostname:'lab',observed_at:'2026-10-02T00:00:00Z',cpu_percent:10,memory_percent:null,disk_percent:5,rx_bytes:'10000',tx_bytes:'1000',wal_pending:100,wal_bytes:1024,errors:[],capture_status:'unmanaged'}
const group={id:'group_1',kind:'groups',revision:1,data:{name:'办公区',owner:'网络团队',description:'',active:true},created_at:'2026-10-01T00:00:00Z',updated_at:'2026-10-01T00:00:00Z'}
const audit={id:'100',username:'operator',action:'sensor.active=false',source_ip:'192.0.2.1',user_agent:'Browser',request_id:'request_1',created_at:'2026-10-01T00:00:00Z'}
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/sensors')?{items:[sensor]}:path.startsWith('/tasks')?{items:[{...task,state:'succeeded'}]}:path==='/health'?health:path==='/network/interfaces'?{items:[iface]}:path==='/capture-config'?{interfaces:['eth0'],status:'not_applied'}:path==='/alerts/search'?{items:[alert],total:1,page:1,page_size:20}:path.includes('/history')?{items:[group]}:path.startsWith('/inventory')?{items:[group],next_cursor:''}:path.startsWith('/audits')?{items:[audit],next_cursor:'100'}:path==='/platform/health'?{services:{postgresql:'ready'},runtime:{...health,commit:'test',heap_bytes:'1024',goroutines:10}}:{items:[],available:true,fields:[]}));vi.spyOn(message,'success').mockImplementation(closedMessage);vi.spyOn(message,'error').mockImplementation(closedMessage)})
async function workspace(component:Component,path:string){const url=new URL('https://test'+path),router=createRouter({history:createMemoryHistory(),routes:[{path:url.pathname,component}]});await router.push(path);await router.isReady();const wrapper=mount(component,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return {wrapper,router}}

 describe('探针列表和诊断',()=>{
 it('列表状态操作保持原探针绑定，保存失败明确反馈',async()=>{
  const{wrapper}=await workspace(SensorsWorkspace,'/sensors');expect(wrapper.text()).toContain('10.0%');expect(wrapper.text()).toContain('未获取');await click('停用');await click('确定');expect(request.mock.calls.find(call=>call[1]?.method==='PATCH')?.[1].body).toEqual({active:false});expect(message.success).toHaveBeenCalledWith('探针状态保存成功')
  request.mockRejectedValueOnce(new Error('保存受阻'));await click('停用');await click('确定');expect(message.error).toHaveBeenCalledWith('保存受阻')
 })
 it('详情使用原探针，诊断受理后跳转单一任务列表',async()=>{
  const{wrapper,router}=await workspace(SensorsWorkspace,'/sensors');await click('查看');await vi.waitFor(()=>expect(document.body.textContent).toContain('18.45 EB'));await click('运行诊断');await flushPromises();expect(router.currentRoute.value.query.view).toBe('tasks');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 it('任务页签返回列表后可查看并关闭探针详情',async()=>{
  const{router}=await workspace(SensorsWorkspace,'/sensors?view=tasks');await click('探针列表');expect(router.currentRoute.value.query.view).toBeUndefined();await click('查看');await vi.waitFor(()=>expect(document.body.textContent).toContain('注册身份'));(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(document.body.textContent).not.toContain('注册身份')
 })
 it('空列表和只读角色保留查看能力，缺测不显示伪造零值',async()=>{
  user.value={...principal,role:'viewer'};request.mockResolvedValue({items:[],next_cursor:''});const{wrapper}=await workspace(SensorsWorkspace,'/sensors?view=tasks');expect(wrapper.text()).toContain('当前条件下没有探针');expect(wrapper.findAll('[role=tab]')).toHaveLength(3);expect(wrapper.text()).toContain('质量事件');request.mockResolvedValueOnce({items:[{...sensor,status:'disabled',active:false,last_seen:null,health:{}}],next_cursor:''});await click('刷新');expect(wrapper.text()).toContain('停用');await click('查看');await vi.waitFor(()=>expect(document.body.textContent).toContain('尚未上报'));expect(document.body.textContent).not.toContain('运行诊断');expect(document.body.textContent).toContain('未获取')
 })
 it('诊断失败保留幂等键，切换对象取消旧响应，离开页面不显示迟到回执',async()=>{
  const wrapper=mount(SensorDetail,{props:{sensor},global,attachTo:document.body});request.mockRejectedValueOnce('offline');await click('运行诊断');expect(message.error).toHaveBeenCalledWith('任务提交失败');const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);const action=button('运行诊断');action.click();action.click();await flushPromises();expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).toBe(key);expect(request.mock.calls).toHaveLength(2);const signal=request.mock.lastCall?.[1].signal as AbortSignal
  await wrapper.setProps({sensor:{...sensor,id:'probe_2'}});expect(signal.aborted).toBe(true);pending.resolve({id:'task_2'});await flushPromises();expect(wrapper.emitted('submitted')).toBeUndefined();expect(message.success).not.toHaveBeenCalled();request.mockResolvedValueOnce({id:'task_3'});await click('运行诊断');expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).not.toBe(key);expect(wrapper.emitted('submitted')).toHaveLength(1)
  await wrapper.setProps({sensor:null});expect(document.body.textContent).not.toContain('探针标识');wrapper.unmount()
 })
 it('捕获状态来自设备心跳，离线保留历史观测且缺失指标不显示零值',async()=>{
  const wrapper=mount(SensorDetail,{props:{sensor:{...sensor,health:{...sensor.health,capture_status:'running',registered_rules_sha256:'b'.repeat(64),capture:{interfaces:['missing'],managed:true,status:'degraded',revision:3,applied_revision:2,applied_settings:{interfaces:['eth0'],threads:1},observed_at:'2026-10-03T01:00:00Z',counters:{'decoder.bytes':'18446744073709551615'},spool_bytes:'1048576',spool_budget:'1073741824',rotation_pending:true}}}},global,attachTo:document.body})
  expect(document.body.textContent).toContain('运行异常');expect(document.body.textContent).toContain('eth0');expect(document.body.textContent).toContain('期望 3 / 生效 2');expect(document.body.textContent).toContain('18.45 EB');expect(document.body.textContent).toContain('持久排空');expect(document.body.textContent).toContain('b'.repeat(64))
  await wrapper.setProps({sensor:{...sensor,status:'offline',health:{capture_status:'eve_reader_only'}}});expect(document.body.textContent).toContain('历史观测');expect(document.body.textContent).toContain('外部 EVE 文件');expect(document.body.textContent).not.toContain('生效采集网卡')
  await wrapper.setProps({sensor:{...sensor,health:{}}});expect(document.body.textContent).toContain('尚未观测');expect(document.body.textContent).not.toContain('历史观测')
 })
 })

 describe('任务记录',()=>{
 it('读取失败不丢弃已知回执，筛选探针清空旧列表，取消只提交一次',async()=>{
  request.mockResolvedValueOnce({items:[task]});const wrapper=mount(TaskWorkspace,{props:{sensorId:sensor.id},global,attachTo:document.body});await flushPromises();expect(request.mock.lastCall?.[0]).toContain('sensor_id=probe_1');request.mockRejectedValueOnce(new Error('读取受阻'));await click('刷新任务');expect(wrapper.text()).toContain('当前显示上次成功读取的状态')
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await click('取消');await click('确定');const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve({ok:true});await flushPromises();expect(message.success).not.toHaveBeenCalled()
 })
 it('未知异常有可读提示，重复失败停止轮询，取消失败保留记录',async()=>{
  vi.useFakeTimers();request.mockRejectedValue('offline');const wrapper=mount(TaskWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('读取失败');await vi.advanceTimersByTimeAsync(5000);await vi.advanceTimersByTimeAsync(10000);const count=request.mock.calls.length;await vi.advanceTimersByTimeAsync(20000);expect(request.mock.calls).toHaveLength(count)
  request.mockResolvedValueOnce({items:[task]});await click('重试');request.mockRejectedValueOnce(new Error('任务已投递'));await click('取消');await click('确定');expect(message.error).toHaveBeenCalledWith('任务已投递');await wrapper.setProps({sensorId:'probe_2'});await flushPromises();expect(request.mock.lastCall?.[0]).toContain('probe_2');wrapper.unmount()
 })
 })

 describe('资产工作区',()=>{
 it('切换账号清除资产编辑和旧列表，查看身份不能进入发现查询',async()=>{
  const{wrapper,router}=await workspace(InventoryWorkspace,'/assets?view=groups');await click('创建资产组');expect(document.body.textContent).toContain('创建资产组');user.value={...principal,id:'another_admin'};await flushPromises();expect(document.body.querySelector('.ant-modal')).toBeNull()
  user.value={...principal,role:'viewer'};await router.push('/assets?view=discovery');await flushPromises();expect(wrapper.text()).toContain('需要管理员权限');expect(wrapper.text()).not.toContain('执行发现');wrapper.unmount()
 })
 it('名称筛选、游标翻页和页签切换保持单一列表，编辑失败保留草稿',async()=>{
  request.mockImplementation((path:string,options?:{method?:string})=>options?.method==='POST'?Promise.reject(new Error('修订冲突')):Promise.resolve(path.includes('/history')?{items:[group]}:{items:[group],next_cursor:'group_1'}));const{wrapper,router}=await workspace(InventoryWorkspace,'/assets?view=groups');await click('下一页');expect(request.mock.lastCall?.[0]).toContain('cursor=group_1');await click('上一页');await wrapper.get('.inventory-search input').setValue('办公区');await wrapper.get('form').trigger('submit');await flushPromises();await vi.waitFor(()=>expect(request.mock.lastCall?.[0]).toContain('keyword=%E5%8A%9E%E5%85%AC%E5%8C%BA'));await click('重置')
  await click('编辑');await click('保存');await vi.waitFor(()=>expect(document.body.textContent).toContain('修订冲突'));await click('取消');await click('办公区');expect(document.body.textContent).toContain('历史修订');(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();await click('网段定义');expect(router.currentRoute.value.query.view).toBe('networks');expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.get('input').element.value).toBe('')
 })
 it('创建和编辑成功关闭弹窗，切换对象取消未完成保存',async()=>{
  const{wrapper}=await workspace(InventoryWorkspace,'/assets?view=groups');await click('创建资产组');const input=document.body.querySelector<HTMLInputElement>('.ant-modal input[id$="_name"]')!;input.value='分支办公区';input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();request.mockResolvedValueOnce(group);await click('保存');await vi.waitFor(()=>expect(document.body.textContent).not.toContain('创建资产组保存'))
  await click('编辑');await click('保存');await vi.waitFor(()=>expect(request.mock.calls.some(call=>call[1]?.method==='POST')).toBe(true));await click('资产目录');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 })

 describe('日志工作区',()=>{
 it('筛选和翻页固定当前窗口，类型切换关闭详情并重置参数',async()=>{
  const wrapper=mount(AuditWorkspace,{props:{category:'operations'},global,attachTo:document.body});await flushPromises();await wrapper.get('form input').setValue('operator');await wrapper.get('form').trigger('submit');await flushPromises();await vi.waitFor(()=>expect(request.mock.lastCall?.[0]).toContain('username=operator'));await click('下一页');await click('上一页');await click('查看');expect(document.body.textContent).toContain('Browser')
  await wrapper.setProps({category:'logins'});await flushPromises();expect(wrapper.text()).toContain('凭据验证结果');expect(wrapper.get('input').element.value).toBe('');expect(document.body.textContent).not.toContain('Browser');await click('重置');await click('刷新');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 it('运行状态、操作日志和登录日志按页签切换且失败可重试',async()=>{
  const{wrapper,router}=await workspace(OperationsWorkspace,'/operations');expect(wrapper.text()).toContain('运行状态');await click('操作日志');expect(router.currentRoute.value.query.view).toBe('operations');request.mockRejectedValueOnce(new Error('日志读取受阻'));await click('刷新');expect(wrapper.text()).toContain('日志读取受阻');await click('重试');await click('登录日志');expect(router.currentRoute.value.query.view).toBe('logins');expect(wrapper.text()).toContain('凭据验证结果')
 })
 })

 describe('采集器管理',()=>{
 it('网卡只展示一张表，保存明确显示待应用，失败保留配置',async()=>{
  const{wrapper,router}=await workspace(CollectorWorkspace,'/network');expect(wrapper.text()).toContain('2001:db8::1/64');expect(wrapper.text()).toContain('未获取');expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('采集配置');expect(router.currentRoute.value.query.view).toBe('capture');expect(wrapper.findAll('.ant-table')).toHaveLength(0);request.mockRejectedValueOnce(new Error('保存受阻'));await click('保存采集目标');expect(message.error).toHaveBeenCalledWith('保存受阻');request.mockResolvedValueOnce({interfaces:['eth0'],status:'not_applied'});await click('保存采集目标');expect(message.success).toHaveBeenCalledWith('采集目标保存成功，等待应用');await click('网卡与状态');request.mockRejectedValueOnce('offline');await click('刷新');expect(wrapper.text()).toContain('读取失败');await click('重试')
  await click('重放样本');await vi.waitFor(()=>expect(wrapper.text()).toContain('PCAP 重放'));await click('任务记录');expect(router.currentRoute.value.query.view).toBe('tasks')
  await click('检测质量');const quality=wrapper.getComponent(DetectionQualityDialog);expect(quality.props('open')).toBe(true);request.mockRejectedValueOnce(new Error('质量观测读取超时'));quality.vm.$emit('refresh');await flushPromises();expect(document.body.textContent).toContain('质量观测读取超时');expect(document.body.textContent).toContain('刷新失败，保留上次观测');quality.vm.$emit('refresh');await flushPromises();expect(quality.props('error')).toBe('');quality.vm.$emit('close');await flushPromises();expect(quality.props('open')).toBe(false)
 })
 it('接口能力和已保存配置保持独立，回环与关闭接口无法选择',async()=>{
  const wrapper=mount(CaptureForm,{props:{interfaces:[iface,{...iface,name:'lo',loopback:true},{...iface,name:'down',up:false}],capture:{interfaces:['eth0'],status:'not_applied'},saving:false},global});const select=wrapper.getComponent(Select);expect(select.props('options')).toMatchObject([{disabled:false},{disabled:true},{disabled:true}]);await select.setValue(['eth0'],'value');await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('save')).toEqual([[{interfaces:['eth0'],threads:1,bpf_filter:'',promiscuous:true}]]);await wrapper.setProps({capture:{interfaces:[],status:'not_applied'},saving:true});expect(select.props('value')).toEqual([]);expect(select.props('disabled')).toBe(true)
  const table=mount(InterfaceTable,{props:{items:[{...iface,name:'lo',loopback:true,up:false,mac:'',addresses:[]}]},global});expect(table.text()).toContain('未提供');expect(table.text()).toContain('未配置');expect(table.text()).toContain('回环');const summary=mount(HealthSummary,{props:{health:{...health,errors:['cpu_unavailable']}},global});expect(summary.text()).toContain('CPU 指标不可用')
 })
 })

 describe('告警检索',()=>{
 it('查询等待期间锁定条件，标签关联控件且恢复后提交完整当前输入',async()=>{
  const wrapper=mount(AlertFilters,{props:{pending:false},global,attachTo:document.body})
  for(const [name,label] of Object.entries({keyword:'关键词',source_ip:'源 IP',destination_ip:'目的 IP',protocol:'协议',method:'请求方法',path:'路径前缀',severity:'严重级别'})){
   const id=`alert-filters_${name}`;expect(wrapper.get(`label[for="${id}"]`).text()).toBe(label);expect(wrapper.get(`#${id}`).element.tagName).toBe('INPUT')
  }
  expect(wrapper.get('label[for="alert-filters-hours"]').text()).toBe('时间范围');expect(wrapper.get('#alert-filters-hours').attributes('role')).toBe('combobox')
  await wrapper.get('#alert-filters_source_ip').setValue('2001:db8::1');await wrapper.get('#alert-filters_destination_ip').setValue('192.0.2.20');await wrapper.get('#alert-filters_protocol').setValue('http');await wrapper.get('#alert-filters_path').setValue('/api/')
  await wrapper.setProps({pending:true});expect(wrapper.findAll('input').every(input=>(input.element as HTMLInputElement).disabled)).toBe(true);expect(button('重置').disabled).toBe(true);await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('search')).toBeUndefined()
  await wrapper.setProps({pending:false});expect(wrapper.findAll('input').every(input=>!(input.element as HTMLInputElement).disabled)).toBe(true);await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('search')).toEqual([[{keyword:'',source_ip:'2001:db8::1',destination_ip:'192.0.2.20',protocol:'http',method:'',path:'/api/',severity:'',filter:''},24]])
  await click('重置');expect(wrapper.get<HTMLInputElement>('#alert-filters_source_ip').element.value).toBe('');expect(wrapper.emitted('search')).toHaveLength(2)
 })
 it('告警列表按范围检索，详情展示 MAC、64 位流标识和载荷权限',async()=>{
  const{wrapper}=await workspace(AlertsWorkspace,'/alerts');await click('查看');expect(document.body.textContent).toContain('18446744073709551614');expect(document.body.textContent).toContain('02:00:00:00:00:01');expect(document.body.textContent).toContain('00000000');(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();await click('刷新');expect(request.mock.lastCall?.[1].body.page).toBe(1)
  request.mockResolvedValueOnce({items:[alert],total:11000,page:1,page_size:20});await click('刷新');expect(wrapper.text()).toContain('10,000');const table=wrapper.getComponent(AlertTable);table.vm.$emit('page',2,50);await flushPromises();expect(request.mock.lastCall?.[1].body).toMatchObject({page:2,page_size:50});const detail=mount(AlertDetail,{props:{alert:{...alert,source:{},destination:{},http:{},network:{},suricata:{},event:{kind:'alert',original:''}}},global,attachTo:document.body});expect(document.body.textContent).toContain('当前账号未获原始载荷读取权限');expect(document.body.textContent).toContain('未观测到');detail.unmount()
 })
 it('高级表达式先校验，失败保留输入，等待校验阻止重复查询',async()=>{
  const wrapper=mount(AlertFilters,{props:{pending:false},global,attachTo:document.body});await wrapper.get('input').setValue('draft');await click('高级检索');await wrapper.get('textarea').setValue('tcp.port in {80 443}');request.mockRejectedValueOnce(new Error('第 1 行第 4 列：字段无效'));await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.text()).toContain('第 1 行第 4 列');expect(wrapper.emitted('search')).toBeUndefined()
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await wrapper.get('form').trigger('submit');await wrapper.get('form').trigger('submit');await flushPromises();expect(request.mock.calls.filter(call=>call[0]==='/search/validate')).toHaveLength(2);pending.resolve({valid:true});await flushPromises();expect(wrapper.emitted('search')?.[0]?.[0]).toMatchObject({keyword:'',filter:'tcp.port in {80 443}'})
  await click('重置');expect(wrapper.emitted('search')).toHaveLength(2);await wrapper.get('textarea').setValue('');await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('search')).toHaveLength(3)
 })
 it('字段目录只插入可信字段，重试取消旧读取并关闭页面请求',async()=>{
  request.mockRejectedValueOnce(new Error('字段目录读取超时'));const wrapper=mount(AdvancedFilter,{props:{modelValue:'',disabled:false},global,attachTo:document.body});await flushPromises();await click('字段目录');expect(document.body.textContent).toContain('字段目录读取超时');request.mockResolvedValueOnce({fields:[{name:'tcp',label:'TCP',type:'protocol',aliases:[],operators:[]},{name:'source.ip',label:'源地址',type:'ip',aliases:['ip.src'],operators:['==']}]});await click('重试');await click('tcp');expect(wrapper.emitted('update:modelValue')?.[0]?.[0]).toBe('tcp');await wrapper.setProps({modelValue:'tcp'});await click('字段目录');const query=document.body.querySelector<HTMLInputElement>('input[aria-label="查找检索字段"]')!;query.value='ip.src';query.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();await click('source.ip');expect(wrapper.emitted('update:modelValue')?.[1]?.[0]).toBe('tcp and source.ip == ');const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true)
 })
 })
