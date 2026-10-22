import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {defineComponent,h,shallowRef,type ShallowRef} from 'vue'
import {createMemoryHistory} from 'vue-router'
import {Menu} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {CaptureConfig,HostHealth,Principal} from '../packages/shared/src/types'
import type {ProtocolReport} from '../packages/shared/src/protocols'
import {protocolLimitNames} from '../packages/shared/src/protocols'
import {collectorMeta,collectorNavigation,collectorScreen,collectorScreens} from '../collector/src/navigation'
import {createCollectorRouter} from '../collector/src/router'
import App from '../collector/src/App.vue'
import CollectorWorkspace from '../collector/src/features/network/CollectorWorkspace.vue'
import {useCollector} from '../collector/src/features/network/useCollector'
import {useCollectorDiagnostics} from '../collector/src/features/network/useCollectorDiagnostics'
import {session} from '../collector/src/session'
import RuleEditor from '../packages/shared/src/components/RuleEditor.vue'
import CaptureForm from '../packages/shared/src/components/CaptureForm.vue'
import ProtocolCapabilitiesDialog from '../packages/shared/src/components/ProtocolCapabilitiesDialog.vue'
import DetectionQualityDialog from '../packages/shared/src/components/DetectionQualityDialog.vue'
import {click,deferred,principal,rules,sample,task,writeRule} from './fixtures'

const {request,restore,login,logout}=vi.hoisted(()=>({request:vi.fn(),restore:vi.fn(),login:vi.fn(),logout:vi.fn()}))
vi.mock('../collector/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null),pending:(await import('vue')).shallowRef(false),error:(await import('vue')).shallowRef(''),restore,login,logout}}))
const user=session.current as ShallowRef<Principal|null>
const mounted:VueWrapper[]=[]
afterEach(()=>{for(const wrapper of mounted)wrapper.unmount();mounted.length=0})
const iface={name:'eth0',index:1,mac:'02:00:00:00:00:01',mtu:1500,up:true,loopback:false,addresses:['192.0.2.1/24','2001:db8::1/64']}
const health:HostHealth={version:'engineering-test',hostname:'probe-local',observed_at:'2026-10-22T00:00:00Z',cpu_percent:12,memory_percent:null,disk_percent:30,rx_bytes:'1000',tx_bytes:'200',wal_pending:3,wal_bytes:300,errors:[],capture_status:'unmanaged'}
const capture:CaptureConfig={interfaces:['eth0'],status:'not_applied'}
const identity={mode:'managed',sensor_id:'probe_local',registration_id:'reg_local',fingerprint_sha256:'a'.repeat(64),not_before:'2026-10-22T00:00:00Z',renew_after:'2026-10-22T02:00:00Z',not_after:'2026-10-22T03:00:00Z'}
const protocolReport:ProtocolReport={schema_version:1,state:'observed',observed_at:'2026-10-22T00:00:00Z',source:'managed_configuration',capture_active:true,engine_version:'8.0.7',engine_sha256:'a'.repeat(64),config_sha256:'b'.repeat(64),protocols:[{protocol:'http',name:'HTTP/1',bindings:[{transport:'tcp',mode:'yes'}],native_listed:true,recognition:'configured',transactions:'configured',online_rules:'requires_validation',file_extraction:'not_implemented',packet_forensics:'not_implemented',external_logs:'not_implemented',qualification:'not_qualified'}],limits:Object.keys(protocolLimitNames).map(key=>({key,value:'32mb'}))}
function respond(path:string){
  return Promise.resolve(path==='/health'?health:path==='/network/interfaces'?{items:[iface]}:path==='/capture-config'?capture:path==='/identity'?identity:path==='/packet-archives'?{items:[],limit:200,available:true}:path==='/replay/samples'?{items:[],available:true}:path==='/response-config-check'?{}:{items:[]})
}
beforeEach(()=>{
  user.value=principal;request.mockReset().mockImplementation(respond);restore.mockReset().mockResolvedValue(undefined)
  login.mockReset().mockResolvedValue(false);logout.mockReset().mockResolvedValue(undefined)
})
async function at(path:string){const router=createCollectorRouter(createMemoryHistory());await router.push(path);await router.isReady();return router}
async function app(path:string){const router=await at(path);const wrapper=mount(App,{global:{plugins:[registerAnt,router]},attachTo:document.body});mounted.push(wrapper);await flushPromises();return {wrapper,router}}

describe('采集器实际层级路由',()=>{
  it('九个实际视图都有父子匹配、中文名称及管理员契约',async()=>{
    const router=await at('/overview/status')
    expect(collectorScreens).toHaveLength(9)
    for(const screen of collectorScreens){
      const resolved=router.resolve(screen.path)
      expect(resolved.matched).toHaveLength(2)
      expect(resolved.matched.at(-1)?.components?.default).toBeTruthy()
      expect(resolved.meta).toMatchObject({admin:true,title:screen.title,workspaceView:screen.view,navWorkspace:screen.workspace})
      expect(collectorScreen(screen.view)).toBe(screen)
    }
    expect(collectorScreen('not-a-view')).toBeUndefined()
    expect(collectorNavigation(false)).toEqual([])
    expect(collectorNavigation(true).map(item=>item.title)).toEqual(['运行状态','网络与采集','平台接入','规则与任务','联动设备'])
    expect(collectorMeta('capture').allowedViews).toEqual(['interfaces','capture','archives','syslog'])
  })
  it.each([
    ['/','/overview/status'],['/overview','/overview/status'],['/network','/network/interfaces'],
    ['/connection','/connection/identity'],['/rules','/rules/samples'],['/response','/response/devices'],
  ])('父级 %s 进入 %s 并保留原业务条件',async(path,expected)=>{
    const router=await at(path+'?source=pcap&mode=inspect#trace')
    expect(router.currentRoute.value.fullPath).toBe(expected+'?source=pcap&mode=inspect#trace')
  })
  it.each([
    ['interfaces','/network/interfaces'],['capture','/network/capture'],['archives','/network/archives'],
    ['samples','/rules/samples'],['tasks','/rules/tasks'],['responses','/response/devices'],['syslog','/network/syslog'],
  ])('旧 view=%s 迁移至 %s，原任务和检索条件不丢失',async(view,path)=>{
    const router=await at('/network?view='+view+'&task=localtask_original&source=pcap&mode=inspect#trace')
    expect(router.currentRoute.value.fullPath).toBe(path+'?task=localtask_original&source=pcap&mode=inspect#trace')
    expect(router.currentRoute.value.query.view).toBeUndefined()
  })
  it.each(['view=invalid','view=tasks&view=capture','view'])('非法旧选择 %s 仅移除选择参数',async(query)=>{
    const router=await at('/network?'+query+'&source=pcap#trace')
    expect(router.currentRoute.value.fullPath).toBe('/network/interfaces?source=pcap#trace')
  })
  it('规范路径消费旧选择且不丢业务模式和任务链接',async()=>{
    const router=await at('/rules/samples?view=tasks&task=localtask_original&mode=inspect#trace')
    expect(router.currentRoute.value.fullPath).toBe('/rules/tasks?task=localtask_original&mode=inspect#trace')
    await router.push('/network/capture?view=invalid&source=mirror&mode=inspect#capture')
    expect(router.currentRoute.value.fullPath).toBe('/network/capture?source=mirror&mode=inspect#capture')
  })
  it('未登录和认证恢复失败保留规范回跳，非管理员转入访问边界',async()=>{
    user.value=null;const router=await at('/network?view=capture&source=mirror#capture')
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.redirect).toBe('/network/capture?source=mirror#capture')
    restore.mockRejectedValueOnce(new Error('认证暂不可用'));await router.push('/rules/tasks?task=localtask_original')
    expect(router.currentRoute.value.query.redirect).toBe('/rules/tasks?task=localtask_original')
    user.value={...principal,role:'viewer'};await router.push('/overview/status')
    expect(router.currentRoute.value.path).toBe('/access-denied')
    expect(router.currentRoute.value.query.redirect).toBe('/overview/status')
    expect(request).not.toHaveBeenCalled()
  })
})

describe('采集器管理页面的实际导航',()=>{
  it.each(collectorScreens.map(screen=>[screen.path,screen.title]))('%s 显示唯一页面标题 %s',async(path,title)=>{
    const {wrapper}=await app(path!)
    await vi.waitFor(()=>expect(wrapper.get('h1').text()).toBe(title))
    expect(wrapper.findAll('.ant-table')).toHaveLength(path==='/network/interfaces'?1:0)
    expect(document.title).toContain(title!)
  })
  it('运行概况保留真实资源与缺测，网卡页只有接口列表',async()=>{
    const {wrapper,router}=await app('/overview/status')
    expect(wrapper.text()).toContain('12.0%');expect(wrapper.text()).toContain('未获取');expect(wrapper.text()).toContain('probe-local')
    expect(request.mock.calls.map(call=>call[0])).toEqual(['/health'])
    request.mockClear();await router.push('/network/interfaces');await flushPromises()
    expect(wrapper.text()).toContain('2001:db8::1/64');expect(wrapper.text()).not.toContain('CPU 使用率')
    expect(request.mock.calls.map(call=>call[0])).toEqual(['/network/interfaces'])
    expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  })
  it('运行状态缺失展示空态，刷新后读取真实观测，不误显示采集表单',async()=>{
    request.mockResolvedValueOnce(null)
    const {wrapper}=await app('/overview/status')
    expect(wrapper.text()).toContain('尚未取得本机运行状态');expect(wrapper.find('.capture-form').exists()).toBe(false)
    await click('刷新');expect(wrapper.text()).toContain('12.0%');expect(wrapper.text()).not.toContain('尚未取得本机运行状态')
  })
  it('状态读取失败给出独立重试，成功回读后清除错误',async()=>{
    request.mockRejectedValueOnce(new Error('状态暂不可用'))
    const {wrapper}=await app('/overview/status')
    expect(wrapper.text()).toContain('状态暂不可用');expect(wrapper.text()).not.toContain('12.0%')
    await click('重试');expect(wrapper.text()).toContain('12.0%');expect(wrapper.text()).not.toContain('状态暂不可用')
  })
  it('网络页签只显示同工作区，切换保留业务条件并可后退前进',async()=>{
    const {wrapper,router}=await app('/network/interfaces?source=mirror&mode=inspect#capture')
    expect(wrapper.findAll('[role=tab]').map(tab=>tab.text())).toEqual(['网卡列表','采集配置','原包归档','Syslog 接收'])
    await click('采集配置');expect(router.currentRoute.value.fullPath).toBe('/network/capture?source=mirror&mode=inspect#capture')
    expect(wrapper.findAll('.ant-table')).toHaveLength(0)
    router.back();await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/network/interfaces'))
    router.forward();await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/network/capture'))
    expect(wrapper.findAll('.shell-breadcrumb .ant-breadcrumb-link').map(item=>item.text())).toEqual(['网络与采集','采集配置'])
  })
  it('侧栏跨工作区不携带专属任务，其他业务条件保留',async()=>{
    const {wrapper,router}=await app('/rules/tasks?task=task_old&source=pcap&mode=inspect#trace')
    wrapper.getComponent(Menu).vm.$emit('click',{key:'workspace:network'});await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/network/interfaces?source=pcap&mode=inspect#trace')
    expect(wrapper.getComponent(Menu).props('selectedKeys')).toEqual(['workspace:network'])
    expect(wrapper.findAll('[role=tab]').map(tab=>tab.text())).not.toContain('重放样本')
  })
  it('任务页切到样本清除任务选择，原始空态与入口可操作',async()=>{
    const {wrapper,router}=await app('/rules/tasks?task=task_old&source=pcap&mode=inspect#trace')
    await click('重放样本');expect(router.currentRoute.value.fullPath).toBe('/rules/samples?source=pcap&mode=inspect#trace')
    await vi.waitFor(()=>expect(wrapper.text()).toContain('PCAP 重放'))
    await click('任务记录');expect(router.currentRoute.value.fullPath).toBe('/rules/tasks?source=pcap&mode=inspect#trace')
  })
  it('实际重放受理后进入原任务规范详情，保留业务条件且不读取旧任务',async()=>{
    const id='localtask_owned',started=new Date(Date.now()-60000).toISOString(),finished=new Date(Date.now()-59000).toISOString()
    const archive={...task,id,kind:'rules.replay',origin:'local',acknowledged:true,retention_protected:false,state:'succeeded',created_at:new Date(Date.now()-61000).toISOString(),expires_at:new Date(Date.now()-30000).toISOString(),retain_until:new Date(Date.now()+86400000).toISOString(),receipt:{command_id:id,command_sha256:'a'.repeat(64),state:'succeeded',started_at:started,finished_at:finished,result:{}}}
    request.mockImplementation((path:string)=>path==='/replay/samples'?Promise.resolve({items:[sample],available:true}):path==='/replay/tasks'?Promise.resolve({id}):path==='/tasks/'+id?Promise.resolve(archive):respond(path))
    const {wrapper,router}=await app('/rules/samples?task=task_old&source=pcap&mode=inspect#trace')
    await click('重放测试');await writeRule(wrapper.getComponent(RuleEditor),rules);await click('执行重放');await click('查看任务记录')
    await vi.waitFor(()=>expect(router.currentRoute.value.fullPath).toBe('/rules/tasks?task='+id+'&source=pcap&mode=inspect#trace'))
    await vi.waitFor(()=>expect(document.body.textContent).toContain('记录保留截止'))
    expect(request.mock.calls.some(call=>call[0]==='/tasks/task_old')).toBe(false)
    expect(request.mock.calls.filter(call=>call[0]==='/replay/tasks')).toHaveLength(1)
    expect(request.mock.calls.some(call=>call[0]==='/tasks/'+id)).toBe(true)
  })
  it('离开规范路径取消在途查询，迟到旧观测不能恢复',async()=>{
    const wait=deferred<unknown>();request.mockImplementation(path=>path==='/network/interfaces'?wait.promise:respond(path))
    const {wrapper,router}=await app('/network/interfaces')
    const signal=request.mock.calls.find(call=>call[0]==='/network/interfaces')![1].signal as AbortSignal
    await router.push('/overview/status');await flushPromises();expect(signal.aborted).toBe(true)
    wait.resolve({items:[{...iface,name:'obsolete-interface'}]});await flushPromises()
    expect(wrapper.get('h1').text()).toBe('运行状态');expect(wrapper.text()).not.toContain('obsolete-interface')
  })
  it('撤销管理员权限立即停止管理请求、清除导航并允许返回登录',async()=>{
    const wait=deferred<unknown>();request.mockImplementation(path=>path==='/network/interfaces'?wait.promise:respond(path))
    const {wrapper,router}=await app('/network/interfaces?source=mirror#trace')
    const signal=request.mock.lastCall![1].signal as AbortSignal,count=request.mock.calls.length
    user.value={...principal,role:'viewer'}
    await vi.waitFor(()=>expect(router.currentRoute.value.path).toBe('/access-denied'))
    expect(signal.aborted).toBe(true);expect(request).toHaveBeenCalledTimes(count)
    expect(wrapper.getComponent(Menu).props('items')).toEqual([])
    wait.resolve({items:[iface]});await flushPromises();expect(wrapper.text()).not.toContain('2001:db8::1/64')
    await click('返回登录');expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.redirect).toBe('/network/interfaces?source=mirror#trace')
    user.value=null;await flushPromises();expect(router.currentRoute.value.path).toBe('/login')
  })
  it('无权限页拒绝外部回跳，退出失败保留页面并允许重试',async()=>{
    user.value={...principal,role:'viewer'};const {wrapper,router}=await app('/access-denied?redirect=https://example.test')
    expect(request).not.toHaveBeenCalled()
    logout.mockRejectedValueOnce(new Error('退出暂不可用'));await click('退出');expect(router.currentRoute.value.path).toBe('/access-denied')
    await click('返回登录');expect(router.currentRoute.value.query.redirect).toBe('/overview/status')
    user.value=principal;await router.push('/overview/status');await flushPromises();await click('退出');expect(router.currentRoute.value.path).toBe('/login')
    expect(wrapper.text()).toContain('登录采集器')
  })
  it('非管理员直接挂载管理组件也不会读取本地接口',async()=>{
    user.value={...principal,role:'viewer'}
    const router=await at('/access-denied')
    const wrapper=mount(CollectorWorkspace,{global:{plugins:[registerAnt,router]}});mounted.push(wrapper);await flushPromises()
    expect(wrapper.text()).toContain('没有采集器本地管理权限');expect(request).not.toHaveBeenCalled()
  })
})

describe('采集器观测作用域',()=>{
  function host(resources:ShallowRef<('health'|'interfaces'|'capture')[]>){let state!:ReturnType<typeof useCollector>;const wrapper=mount(defineComponent({setup(){state=useCollector({resources:()=>resources.value});return ()=>h('div')}}));mounted.push(wrapper);return {state,wrapper}}
  it('仅加载所需来源，空权限作用域不读取或保存配置',async()=>{
    const resources=shallowRef<('health'|'interfaces'|'capture')[]>([]),{state}=host(resources);await flushPromises()
    expect(state.pending.value).toBe(false);expect(request).not.toHaveBeenCalled();expect(await state.save(['eth0'])).toBe(false)
    resources.value=['health'];await flushPromises();expect(request.mock.calls.map(call=>call[0])).toEqual(['/health'])
    expect(state.health.value?.hostname).toBe('probe-local');expect(state.interfaces.value).toEqual([])
    resources.value=['interfaces'];await flushPromises();expect(state.health.value).toBeNull();expect(state.interfaces.value).toEqual([iface])
    resources.value=[];await flushPromises();expect(state.interfaces.value).toEqual([])
    const count=request.mock.calls.length;await state.refresh();expect(request).toHaveBeenCalledTimes(count)
  })
  it('权限变化取消配置写入，取消错误不产生迟到失败消息',async()=>{
    const resources=shallowRef<('health'|'interfaces'|'capture')[]>(['capture']),{state,wrapper}=host(resources);await flushPromises()
    const wait=deferred<unknown>();request.mockReturnValueOnce(wait.promise)
    const saving=state.save(['eth0']),signal=request.mock.lastCall![1].signal as AbortSignal
    resources.value=[];expect(signal.aborted).toBe(true);expect(state.saving.value).toBe(false)
    wait.reject(new DOMException('取消','AbortError'));expect(await saving).toBe(false)
    expect(state.capture.value.interfaces).toEqual([]);wrapper.unmount();await state.refresh()
  })
  it('配置提交期间不并发读取旧版本，提交完成后可显式刷新',async()=>{
    const resources=shallowRef<('health'|'interfaces'|'capture')[]>(['capture']),{state}=host(resources);await flushPromises()
    const wait=deferred<unknown>();request.mockReturnValueOnce(wait.promise)
    const saving=state.save(['eth0']),count=request.mock.calls.length
    await state.refresh();expect(request).toHaveBeenCalledTimes(count)
    wait.resolve({...capture,status:'running'});expect(await saving).toBe(true);expect(state.capture.value.status).toBe('running')
    request.mockResolvedValueOnce({...capture,status:'stopped'});await state.refresh();expect(state.capture.value.status).toBe('stopped')
  })
})

describe('采集器诊断与采集草稿隔离',()=>{
  it.each(['协议能力','检测质量'])('编辑草稿后打开、刷新和关闭%s不卸载表单或提交配置',async(label)=>{
    const opening=deferred<CaptureConfig>(),baseline:CaptureConfig={...capture,threads:1,bpf_filter:'',revision:1}
    const changed:CaptureConfig={...baseline,threads:4,bpf_filter:'udp port 53',revision:2}
    let reads=0
    request.mockImplementation(path=>path==='/capture-config'?++reads===1?Promise.resolve(baseline):reads===2?opening.promise:Promise.resolve(changed):respond(path))
    const {wrapper}=await app('/network/capture')
    const form=wrapper.getComponent(CaptureForm),bpf=wrapper.get<HTMLInputElement>('#capture-bpf'),threads=wrapper.get<HTMLInputElement>('#capture-threads')
    await bpf.setValue('tcp port 8080');await threads.setValue('7')
    const checkDraft=()=>{expect(wrapper.getComponent(CaptureForm).element).toBe(form.element);expect(wrapper.get<HTMLInputElement>('#capture-bpf').element).toBe(bpf.element);expect(bpf.element.value).toBe('tcp port 8080');expect(threads.element.value).toBe('7')}
    await click(label);checkDraft()
    const dialog=label==='协议能力'?wrapper.getComponent(ProtocolCapabilitiesDialog):wrapper.getComponent(DetectionQualityDialog)
    expect(dialog.props().loading).toBe(true)
    opening.resolve(changed);await flushPromises();checkDraft()
    await click('刷新观测');checkDraft();expect(dialog.props().loading).toBe(false)
    document.querySelector<HTMLButtonElement>('.ant-modal-close')!.click();await flushPromises();checkDraft()
    expect(dialog.props().open).toBe(false)
    expect(request.mock.calls.filter(call=>call[0]==='/network/interfaces')).toHaveLength(1)
    expect(request.mock.calls.filter(call=>call[1]?.method==='PUT')).toHaveLength(0)
    expect(form.props('capture')).toEqual(baseline)
  })
  it.each(['/health','/capture-config'])('样本页面诊断读取%s失败可见、可重试且刷新失败保留完整旧观测',async(failedPath)=>{
    let failed=true
    let observedHealth={...health,protocol_capabilities:protocolReport}
    const observedCapture:CaptureConfig={...capture,revision:3,config_sha256:'b'.repeat(64)}
    request.mockImplementation(path=>path===failedPath&&failed?Promise.reject(new Error('诊断来源暂不可用')):path==='/health'?Promise.resolve(observedHealth):path==='/capture-config'?Promise.resolve(observedCapture):respond(path))
    const {wrapper}=await app('/rules/samples')
    await click('协议能力')
    expect(document.body.textContent).toContain('协议能力读取失败')
    expect(document.body.textContent).toContain('诊断来源暂不可用')
    expect(document.body.textContent).not.toContain('尚无可核对的协议能力观测')
    expect(document.body.textContent).not.toContain('旧采集器可能尚未上报')
    const dialog=wrapper.getComponent(ProtocolCapabilitiesDialog)
    expect(dialog.props('capture')).toBeUndefined()
    failed=false;await click('刷新观测')
    expect(document.body.textContent).toContain('HTTP/1');expect(dialog.props('error')).toBe('')
    const previous=dialog.props('report')
    observedHealth={...health,protocol_capabilities:{...protocolReport,observed_at:'2026-10-22T01:00:00Z'}}
    failed=true;await click('刷新观测')
    expect(document.body.textContent).toContain('刷新失败，保留上次观测')
    expect(document.body.textContent).toContain('HTTP/1')
    expect(dialog.props('report')).toBe(previous);expect(dialog.props('capture')).toBe(observedCapture)
    expect(wrapper.get('h1').text()).toBe('重放样本')
    expect(request.mock.calls.some(call=>call[1]?.method==='PUT')).toBe(false)
  })
})

describe('采集器独立诊断请求边界',()=>{
  function host(){
    const enabled=shallowRef(true),open=shallowRef(false)
    let state!:ReturnType<typeof useCollectorDiagnostics>
    const wrapper=mount(defineComponent({setup(){state=useCollectorDiagnostics({enabled:()=>enabled.value,open:()=>open.value});return()=>h('div')}}));mounted.push(wrapper)
    return{state,wrapper,enabled,open}
  }
  it('默认不读取，关闭取消未完成请求，迟到结果不覆盖缓存',async()=>{
    const {state,open}=host();await flushPromises();expect(request).not.toHaveBeenCalled()
    open.value=true;await flushPromises();expect(state.capture.value).toBe(capture)
    const late=deferred<CaptureConfig>();request.mockImplementation(path=>path==='/capture-config'?late.promise:respond(path))
    const refreshing=state.refresh(),signal=request.mock.lastCall![1].signal as AbortSignal
    open.value=false;expect(signal.aborted).toBe(true);expect(state.pending.value).toBe(false)
    late.resolve({...capture,revision:999});await refreshing
    expect(state.capture.value).toBe(capture);expect(state.error.value).toBe('')
    const count=request.mock.calls.length;await state.refresh();expect(request).toHaveBeenCalledTimes(count)
  })
  it('权限撤回和卸载清除缓存，未完成诊断不会恢复旧权限数据',async()=>{
    const {state,enabled,open,wrapper}=host();open.value=true;await flushPromises();expect(state.health.value).toBe(health)
    const late=deferred<CaptureConfig>();request.mockImplementation(path=>path==='/capture-config'?late.promise:respond(path))
    const refreshing=state.refresh(),signal=request.mock.lastCall![1].signal as AbortSignal
    enabled.value=false;expect(signal.aborted).toBe(true);expect(state.health.value).toBeNull();expect(state.capture.value).toBeUndefined()
    late.resolve({...capture,revision:999});await refreshing;expect(state.capture.value).toBeUndefined()
    request.mockImplementation(respond);enabled.value=true;await flushPromises();expect(state.health.value).toBe(health)
    wrapper.unmount();await state.refresh();expect(state.health.value).toBeNull()
  })
  it('部分读取失败取消同批请求，保留旧快照并返回可读错误',async()=>{
    const {state,open}=host();open.value=true;await flushPromises()
    const oldHealth=state.health.value,oldCapture=state.capture.value,wait=deferred<CaptureConfig>()
    request.mockImplementation(path=>path==='/health'?Promise.reject('unavailable'):path==='/capture-config'?wait.promise:respond(path))
    await state.refresh();const signal=request.mock.lastCall![1].signal as AbortSignal
    expect(signal.aborted).toBe(true);expect(state.pending.value).toBe(false);expect(state.error.value).toContain('诊断观测读取失败')
    expect(state.health.value).toBe(oldHealth);expect(state.capture.value).toBe(oldCapture)
    wait.reject(new DOMException('取消','AbortError'));await flushPromises()
  })
})
