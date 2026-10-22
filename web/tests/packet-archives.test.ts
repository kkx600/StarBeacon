import {webcrypto} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message,Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiClient,SessionExportError} from '../packages/shared/src/api'
import {packetCapture,packetUnsealed,canDownloadPacket,validPacketPage,validPacketRecord,validSessionReport,type PacketCapture,type PacketRecord,type PacketPage,type SessionExportRequest,type SessionExportReport} from '../packages/shared/src/packetArchives'
import {usePacketArchives} from '../packages/shared/src/usePacketArchives'
import PacketWorkspace from '../packages/shared/src/components/PacketArchiveWorkspace.vue'
import PacketDetail from '../packages/shared/src/components/PacketArchiveDetail.vue'
import SessionExportDialog from '../packages/shared/src/components/SessionExportDialog.vue'
import TrafficWorkspace from '../platform/src/features/traffic/TrafficWorkspace.vue'
import CollectorWorkspace from '../collector/src/features/network/CollectorWorkspace.vue'
import {click,button,deferred,principal} from './fixtures'

const {platformRequest,collectorRequest}=vi.hoisted(()=>({platformRequest:vi.fn(),collectorRequest:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request:platformRequest},current:(await import('vue')).shallowRef(null)}}))
vi.mock('../collector/src/session',async()=>({session:{api:{request:collectorRequest},current:(await import('vue')).shallowRef({id:'u_admin',tenant_id:'t_office',username:'admin',role:'admin',csrf_token:'test-csrf'})}}))
const global={plugins:[registerAnt]}
const stamp='2026-10-03T01:00:00Z'
const capture:PacketCapture={id:'packet_owned',tenant_id:principal.tenant_id,sensor_id:'probe_owned',registration_id:'reg_owned',run_id:'run_owned',interface:'eth0',interface_mac:'02:00:00:00:00:01',settings_sha256:'a'.repeat(64),bpf_filter:'tcp port 8088',promiscuous:false,started_at:stamp,ended_at:'2026-10-03T01:00:03Z',first_packet_at:stamp,last_packet_at:'2026-10-03T01:00:01Z',packets:12,packet_bytes:800,truncated_packets:0,vlan_offload_packets:0,kernel_drops:'0',counter_state:'observed',termination:'rotation',format:'pcapng',source:'AF_PACKET',snap_length:262144}
const record:PacketRecord={id:capture.id,state:'ready',capture,codec:'zstd',raw_bytes:12000,stored_bytes:2500,manifest_sha256:'b'.repeat(64),object_version:'version_owned',created_at:stamp,expires_at:'2027-04-01T01:00:00Z'}
const detail:PacketRecord={...record,manifest:{capture,encoding:{schema:'packet.archive.v1',codec:'zstd',implementation:'klauspost/compress/v1.20.1',level:'SpeedFastest',frame_bytes:262144,raw_bytes:12000,stored_bytes:2500,raw_sha256:'c'.repeat(64),stored_sha256:'d'.repeat(64),frames:[{}]}}}
function unsealedRecord(state='capturing'):PacketRecord{return {id:capture.id,state,capture:{...capture,ended_at:'0001-01-01T00:00:00Z',first_packet_at:null,last_packet_at:null,packets:0,packet_bytes:0,truncated_packets:0,vlan_offload_packets:0,kernel_drops:null,counter_state:'',termination:'',format:'',source:'',snap_length:0},reserved_bytes:3*(16<<20)+(512<<10),created_at:stamp,...(state==='quarantined'?{code:'capture_interrupted'}:{})}}
const exportRequest:SessionExportRequest={archive_ids:[record.id],mode:'full_session',client_ip:'192.0.2.10',client_port:40000,server_ip:'198.51.100.20',server_port:80,client_mac:'02:00:00:00:00:01',server_mac:'02:00:00:00:00:02',vlans:[]}
const exportReport:SessionExportReport={schema:'packet.session.v1',completeness:'snapshot',handshake_status:'not_observed',bidirectional_status:'one_sided',payload_coverage:'gap_detected',payload_visibility:'unknown',termination_status:'not_observed',checksum_validation:'not_checked',packets:3,packet_bytes:500,first_packet_at:stamp,last_packet_at:stamp,reasons:['handshake_not_verified','payload_sequence_gap']}
const page=():PacketPage=>({items:[structuredClone(record)],available:true,next:'cursor-owned'})
const request=vi.fn(),downloadPacket=vi.fn(),api={request,downloadPacket} as unknown as ApiClient
beforeEach(()=>{request.mockReset();downloadPacket.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/packet-archives/')?structuredClone(detail):page()));platformRequest.mockReset();collectorRequest.mockReset();vi.spyOn(message,'success').mockImplementation(()=>undefined as never)})

describe('原包目录响应边界',()=>{
 it('平台摘要、本机活动捕获和冻结详情分别验证',()=>{
  expect(validPacketPage(page())).toBe(true);expect(validPacketRecord(detail,false,true)).toBe(true);expect(packetCapture(detail)).toEqual(capture);expect(packetCapture(record)).toEqual(capture)
  expect(validPacketPage({items:[unsealedRecord()],available:true},true)).toBe(true)
  expect(validPacketPage({items:[],available:false})).toBe(true)
 })
 it('真实本机开始目录可与 199 条已确认记录共存，不把活动元数据当作完整制品',()=>{
  const active=unsealedRecord(),confirmed=Array.from({length:199},(_,index)=>{const id='packet_confirmed_'+index;return {...record,id,state:'confirmed',capture:{...capture,id},reserved_bytes:0}})
  expect(validPacketPage({items:[active,...confirmed],available:true,limit:200},true)).toBe(true)
  expect(validPacketRecord(active,true,true)).toBe(true);expect(packetUnsealed(active)).toBe(true);expect(canDownloadPacket(active)).toBe(false)
  const interrupted=unsealedRecord('quarantined');expect(validPacketRecord(interrupted,true,true)).toBe(true);expect(canDownloadPacket(interrupted)).toBe(false)
  expect(validPacketRecord(active,false)).toBe(false);expect(validPacketRecord({...record,state:'capturing'},true)).toBe(false)
  expect(validPacketPage({items:[active,...confirmed,{...active,id:'packet_extra',capture:{...active.capture!,id:'packet_extra'}}],available:true},true)).toBe(false)
 })
 it('未封存身份与固定空字段必须完整，缺损不得绕过平台或可下载制品检查',()=>{
  const active=unsealedRecord()
  const mutations:Record<string,unknown>[]=[{id:'packet_other'},{sensor_id:''},{interface_mac:'invalid'},{settings_sha256:'bad'},{started_at:'0001-01-01T00:00:00Z'},{format:'pcapng'},{source:'AF_PACKET'},{snap_length:262144},{counter_state:'observed'},{kernel_drops:'0'},{termination:'rotation'},{packets:1},{packet_bytes:1},{first_packet_at:stamp},{last_packet_at:stamp},{ended_at:stamp}]
  for(const patch of mutations)expect(validPacketRecord({...active,capture:{...active.capture!,...patch}},true)).toBe(false)
  for(const patch of [{reserved_bytes:undefined},{reserved_bytes:0},{reserved_bytes:-1},{reserved_bytes:3*(64<<20)+(512<<10)+1},{manifest_sha256:'b'.repeat(64)},{acknowledgement:{}},{created_at:'0001-01-01T00:00:00Z'},{state:'sealed'},{state:'ready'},{state:'confirmed'}])expect(validPacketRecord({...active,...patch},true,true)).toBe(false)
  expect(validPacketRecord({...active,reserved_bytes:3*(64<<20)+(512<<10)},true)).toBe(true)
  for(const ended_at of ['invalid','0001-01-01T00:00:00Z','2026-10-03T00:59:59Z','2026-10-03T02:00:01Z'])expect(validPacketRecord({...record,capture:{...capture,ended_at}})).toBe(false)
 })
 it('非法身份、重复行、缺少摘要和无界响应无法当作成功',()=>{
  for(const value of [null,[],{}, {items:[],available:'yes'}, {...page(),items:[record,record]}, {...page(),next:'x'.repeat(1025)}, {...page(),items:Array(51).fill(record)}])expect(validPacketPage(value)).toBe(false)
  for(const value of [null,{...record,id:'../other'},{...record,state:'invalid'},{...record,created_at:'bad'},{...record,capture:{...capture,id:'other'}},{...record,capture:{...capture,interface_mac:'bad'}},{...record,capture:{...capture,packets:-1}},{...record,capture:{...capture,packet_bytes:65<<20}},{...record,expires_at:'bad'},{...record,stored_bytes:129<<20},{...detail,manifest:{...detail.manifest!,encoding:{...detail.manifest!.encoding,raw_sha256:'bad'}}}])expect(validPacketRecord(value,false,true)).toBe(false)
 })
 it('缺损清单和健康接口不会抛异常或丢失 64 位精度',()=>{
  for(const manifest of [null,[],{}, {capture}, {capture,encoding:null}]){
   const value={...record,manifest};expect(()=>validPacketRecord(value,false,true)).not.toThrow();expect(validPacketRecord(value,false,true)).toBe(false)
  }
  for(const kernel_drops of [0,18446744073709551615n,'18446744073709551616','-1','0.5',''])expect(validPacketRecord({...record,capture:{...capture,kernel_drops}})).toBe(false)
  expect(validPacketRecord({...record,capture:{...capture,kernel_drops:'18446744073709551615'}})).toBe(true)
  expect(validPacketRecord({...record,capture:{...capture,kernel_drops:null,counter_state:'unavailable'}})).toBe(true)
  const health={enabled:true,state:'capturing',codec:'zstd',reserved_bytes:'0',quota_bytes:'18446744073709551615',observed_at:stamp,interfaces:[{id:'packet_owned',interface:'eth0',state:'capturing',packets:'18446744073709551615',observed_at:stamp}]}
  expect(validPacketPage({...page(),health})).toBe(true)
  expect(validPacketPage({...page(),health:{...health,state:'failed',code:'packet_spool_unavailable',reserved_bytes:''}})).toBe(true)
  for(const value of [null,[],{}, {...health,reserved_bytes:0}, {...health,reserved_bytes:''}, {...health,quota_bytes:'18446744073709551616'}, {...health,interfaces:[null]}, {...health,interfaces:[{...health.interfaces[0],interface:'../eth0'}]}, {...health,last_confirmed_id:'../packet'}, {...health,last_confirmed_at:'invalid'}]){
   expect(()=>validPacketPage({...page(),health:value})).not.toThrow();expect(validPacketPage({...page(),health:value})).toBe(false)
  }
  expect(validPacketRecord({...record,capture:{...capture,packets:0,packet_bytes:0,first_packet_at:null,last_packet_at:null}})).toBe(true)
  expect(validPacketRecord({...record,capture:{...capture,last_packet_at:stamp,first_packet_at:'2026-10-03T01:00:02Z'}})).toBe(false)
 })
})

describe('原包确认摘要',()=>{
 it('完整确认保留真实存储大小，拒绝缺损字段、无效对象版本和目录冲突',()=>{
  const acknowledgement={id:record.id,manifest_sha256:'b'.repeat(64),raw_sha256:'c'.repeat(64),stored_sha256:'d'.repeat(64),stored_bytes:2500,object_version:'version_owned',expires_at:record.expires_at!}
  const confirmed={...record,state:'confirmed',acknowledgement}
  expect(validPacketRecord(confirmed,true,true)).toBe(true)
  expect(validPacketRecord({...confirmed,raw_bytes:undefined,stored_bytes:undefined,codec:undefined},true,true)).toBe(true)
  expect(validPacketRecord({...confirmed,object_version:undefined,acknowledgement:{...acknowledgement,object_version:'opaque version'}},true,true)).toBe(true)
  const invalid:unknown[]=[null,[],{},...['id','manifest_sha256','raw_sha256','stored_sha256','stored_bytes','object_version','expires_at'].map(key=>({...acknowledgement,[key]:undefined})),{...acknowledgement,id:'packet_other'},...['bad','0'.repeat(63)].map(value=>({...acknowledgement,stored_sha256:value})),...[0,-1,0.5,129*1024*1024].map(stored_bytes=>({...acknowledgement,stored_bytes})),...['','null','x'.repeat(1025),'v\0','v\n','v\r'].map(object_version=>({...acknowledgement,object_version})),...['invalid','0001-01-01T00:00:00Z'].map(expires_at=>({...acknowledgement,expires_at}))]
  for(const ack of invalid){expect(()=>validPacketRecord({...confirmed,acknowledgement:ack},true,true)).not.toThrow();expect(validPacketRecord({...confirmed,acknowledgement:ack},true,true)).toBe(false)}
  for(const changed of [{manifest_sha256:'e'.repeat(64)},{stored_bytes:2501},{object_version:'other_version'},{manifest:{...detail.manifest!,encoding:{...detail.manifest!.encoding,raw_sha256:'e'.repeat(64)}}},{manifest:{...detail.manifest!,encoding:{...detail.manifest!.encoding,stored_sha256:'e'.repeat(64)}}},{manifest:{...detail.manifest!,encoding:{...detail.manifest!.encoding,stored_bytes:2501}}}])expect(validPacketRecord({...confirmed,...changed},true,true)).toBe(false)
  expect(validPacketRecord({...confirmed,manifest:detail.manifest},true,true)).toBe(true)
 })
})

describe('原包目录工作区',()=>{
 it.each(['capturing','quarantined'])('本机未封存记录 %s 保留身份和待核查提示，不呈现零包结论或下载',async state=>{
  const active=unsealedRecord(state);request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/packet-archives/')?structuredClone(active):{items:[structuredClone(active)],available:true,limit:200}))
  const wrapper=mount(PacketWorkspace,{props:{api,local:true},global,attachTo:document.body});await flushPromises()
  expect(wrapper.text()).not.toContain('响应不完整');expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('待封存');expect(wrapper.text()).toContain('包数与完整性尚未冻结');expect(wrapper.text()).not.toContain('0 包');expect(button('下载').disabled).toBe(true)
  await click('查看');const modal=document.body.querySelector('.ant-modal')!;expect(modal.textContent).toContain('目录只包含捕获开始时的身份');expect(modal.textContent).toContain(state==='capturing'?'正在捕获':'尚未封存');expect(modal.textContent).not.toContain('0 包');expect(modal.textContent).not.toContain('0001');expect(modal.textContent).toContain('不能作为完整通信证据');if(state==='quarantined')expect(modal.textContent).toContain('进程中断时的原包尚未完整封存');expect(downloadPacket).not.toHaveBeenCalled()
 })
 it('单一表格、精确筛选、游标和详情保持正确的对象身份',async()=>{
  const wrapper=mount(PacketWorkspace,{props:{api},global,attachTo:document.body});await flushPromises();expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('12 KB');expect(wrapper.text()).toContain('2.5 KB')
  await wrapper.get('input').setValue('probe_other');await wrapper.get('form').trigger('submit');await flushPromises();expect(request.mock.lastCall?.[0]).toBe('/packet-archives?sensor_id=probe_other')
  await click('下一页');expect(request.mock.lastCall?.[0]).toContain('cursor=cursor-owned');await click('上一页');expect(request.mock.lastCall?.[0]).not.toContain('cursor=');await click('重置');expect(wrapper.get('input').element.value).toBe('')
  await click('查看');expect(document.body.textContent).toContain('原包归档详情');expect(document.body.textContent).toContain('version_owned');expect(document.body.textContent).not.toContain('三次');expect(document.body.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0)
  wrapper.getComponent(PacketDetail).getComponent(Modal).vm.$emit('cancel');await flushPromises();expect(wrapper.getComponent(PacketDetail).props('record')).toBeNull()
 })
 it('未配置、空目录和依赖故障有独立提示，刷新可恢复',async()=>{
  request.mockResolvedValueOnce({items:[],available:false});const wrapper=mount(PacketWorkspace,{props:{api},global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('原包归档未配置');expect(wrapper.text()).toContain('暂无原包归档');expect(wrapper.findAll('.ant-table')).toHaveLength(0)
  request.mockRejectedValueOnce(new Error('原包目录受阻'));await click('刷新原包');expect(wrapper.text()).toContain('原包目录受阻');expect(wrapper.text()).not.toContain('暂无原包归档');await click('重试');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  request.mockResolvedValueOnce({items:[],available:true});await click('刷新原包');expect(wrapper.text()).not.toContain('原包归档未配置')
 })
 it('详情失败可重试，不一致对象不会替换冻结目录',async()=>{
  const wrapper=mount(PacketWorkspace,{props:{api},global,attachTo:document.body});await flushPromises();request.mockRejectedValueOnce(new Error('对象已到期'));await click('查看');expect(document.body.textContent).toContain('对象已到期');await click('重试');expect(document.body.textContent).toContain('c'.repeat(64))
  wrapper.getComponent(PacketDetail).vm.$emit('close');await flushPromises();request.mockResolvedValueOnce({...detail,id:'packet_other'});await click('查看');expect(document.body.textContent).toContain('所选目录不一致');wrapper.unmount()
 })
 it('本机确认记录不可下载，额度和原件保留有明确说明',async()=>{
  request.mockResolvedValueOnce({items:[{...record,state:'confirmed',reserved_bytes:0}],available:true,health:{enabled:true,state:'failed',code:'packet_spool_full',codec:'zstd',reserved_bytes:'1000000',quota_bytes:'1048576',observed_at:stamp,interfaces:[]}})
  const wrapper=mount(PacketWorkspace,{props:{api,local:true},global,attachTo:document.body});await flushPromises();expect(wrapper.find('form').exists()).toBe(false);expect(wrapper.text()).toContain('原包暂存额度已用尽');expect(button('下载').disabled).toBe(true);expect(wrapper.text()).toContain('最近 200 条');expect(wrapper.text()).toContain('1 MB')
  request.mockResolvedValueOnce({...record,state:'confirmed',manifest:undefined,codec:undefined,raw_bytes:undefined,stored_bytes:undefined,acknowledgement:{id:record.id,manifest_sha256:'b'.repeat(64),raw_sha256:'c'.repeat(64),stored_sha256:'d'.repeat(64),stored_bytes:2500,object_version:'version_owned',expires_at:record.expires_at!}});await click('查看');expect(document.body.textContent).toContain('version_owned');expect(document.body.textContent).toContain('已归档数据请在主平台查询')
  const modal=document.querySelector('.ant-modal')!;expect(modal.textContent).not.toContain('制品尚未编码');expect(modal.textContent).toContain('本机只保留确认摘要和捕获目录');expect(modal.textContent).toContain('详见主平台归档');expect(modal.textContent).toContain('未获取 / 2.5 KB')
 })
 it('下载校验成功后才保存，拒绝重复请求，错误与卸载不产生文件',async()=>{
  vi.useFakeTimers();const create=vi.fn(()=> 'blob:owned'),revoke=vi.fn();vi.stubGlobal('URL',Object.assign(class extends URL {},{createObjectURL:create,revokeObjectURL:revoke}));const save=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{})
  const wrapper=mount(PacketWorkspace,{props:{api},global,attachTo:document.body});await flushPromises();const wait=deferred<Blob>();downloadPacket.mockImplementationOnce(()=>wait.promise);await click('下载');expect(button('下载').disabled).toBe(true);wait.resolve(new Blob(['actual verified packets']));await flushPromises();expect(save).toHaveBeenCalledOnce();expect(create).toHaveBeenCalledOnce();await vi.advanceTimersByTimeAsync(1000);expect(revoke).toHaveBeenCalledWith('blob:owned')
  downloadPacket.mockRejectedValueOnce(new Error('指定版本无法确认'));await click('下载');expect(wrapper.text()).toContain('指定版本无法确认')
  const late=deferred<Blob>();downloadPacket.mockImplementationOnce(()=>late.promise);await click('下载');const signal=downloadPacket.mock.lastCall?.[1] as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(new Blob(['late']));await flushPromises();expect(save).toHaveBeenCalledOnce()
 })
 it('缺失计数、卸载、未知版本与未知错误不制造完整性结论',async()=>{
  const wrapper=mount(PacketDetail,{props:{record:{...record,state:'quarantined',code:'unknown',capture:{...capture,counter_state:'unavailable',kernel_drops:null},raw_bytes:undefined,stored_bytes:undefined,expires_at:undefined,object_version:undefined},local:true,pending:false,error:''},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('未获取可靠计数');expect(document.body.textContent).toContain('主平台尚未确认');expect(document.body.textContent).toContain('无法按平台留存时间回收')
  await wrapper.setProps({record:{...record,state:'capturing'}});expect(document.body.textContent).toContain('正在捕获');await wrapper.setProps({record:{...detail,code:'packet_validation_failed'}});expect(document.body.textContent).toContain('原件已保留供核查')
 })
})

describe('原包请求生命周期',()=>{
 function hook(local=false){let state!:ReturnType<typeof usePacketArchives>;const wrapper=mount(defineComponent({setup(){state=usePacketArchives(api,local);return()=>h('div')}}));return{state,wrapper}}
 it('迟到筛选、详情和卸载响应不能覆盖当前列表',async()=>{
  const waiting=deferred<PacketPage>();request.mockImplementationOnce(()=>waiting.promise);const{state,wrapper}=hook(),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.filter(' probe_owned ');await flushPromises();expect(signal.aborted).toBe(true);const selected=state.page.value;waiting.resolve({items:[],available:true});await flushPromises();expect(state.page.value).toBe(selected)
  const pendingDetail=deferred<PacketRecord>();request.mockImplementationOnce(()=>pendingDetail.promise);const open=state.view(record);state.close();pendingDetail.resolve(detail);await open;expect(state.selected.value).toBeNull()
  const pendingList=deferred<PacketPage>();request.mockImplementationOnce(()=>pendingList.promise);state.refresh();await flushPromises();const liveSignal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(liveSignal.aborted).toBe(true);pendingList.resolve(page());await flushPromises()
 })
 it('无游标时不能翻页，格式或未知异常不被当作空成功',async()=>{
  request.mockResolvedValueOnce({items:[],available:true});const{state}=hook();await flushPromises();const calls=request.mock.calls.length;state.next();state.previous();await flushPromises();expect(request).toHaveBeenCalledTimes(calls)
  request.mockResolvedValueOnce({items:null,available:true});state.refresh();await flushPromises();expect(state.error.value).toContain('响应不完整');request.mockRejectedValueOnce('offline');state.refresh();await flushPromises();expect(state.error.value).toBe('原包目录读取失败')
  request.mockRejectedValueOnce('missing');await state.view(record);expect(state.detailError.value).toBe('原包详情读取失败')
 })
})

describe('流量与采集器页签',()=>{
 it('原包页签使用 history 查询参数，只加载一个业务列表',async()=>{
  platformRequest.mockImplementation(()=>Promise.resolve(page()));const router=createRouter({history:createMemoryHistory(),routes:[{path:'/traffic',component:TrafficWorkspace}]});await router.push('/traffic?view=archives');await router.isReady();const wrapper=mount(TrafficWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();await vi.waitFor(()=>expect(wrapper.findAll('.ant-table')).toHaveLength(1));expect(platformRequest.mock.calls.some(c=>c[0]==='/traffic/search')).toBe(false);expect(wrapper.text()).toContain('原包归档')
 })
 it('本机归档入口与重放分开，切换不叠加表格',async()=>{
  collectorRequest.mockImplementation((path:string)=>Promise.resolve(path==='/packet-archives'?{...page(),items:[{...record,reserved_bytes:3<<20}]}:path==='/network/interfaces'?{items:[]}:{}));const router=createRouter({history:createMemoryHistory(),routes:[{path:'/network',component:CollectorWorkspace}]});await router.push('/network?view=archives');await router.isReady();const wrapper=mount(CollectorWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();await vi.waitFor(()=>expect(wrapper.findAll('.ant-table')).toHaveLength(1));expect(wrapper.text()).toContain('最近 200 条');expect(collectorRequest.mock.calls.some(c=>c[0]==='/replay/samples')).toBe(false)
 })
})

describe('原包下载 API',()=>{
 const bytes=new Uint8Array(40).fill(17)
 async function packetResponse(payload:Uint8Array=bytes,headers:Record<string,string>={}){const hash=Buffer.from(await webcrypto.subtle.digest('SHA-256',bytes)).toString('hex');return new Response(new Uint8Array(payload),{headers:{'Content-Type':'application/x-pcapng','Content-Length':String(bytes.length),'X-Content-SHA256':hash,...headers}})}
 it('同源身份读取实际内容，SHA-256 成功后返回有界原包',async()=>{
  vi.stubGlobal('crypto',webcrypto);const fetcher=vi.fn().mockResolvedValue(await packetResponse());vi.stubGlobal('fetch',fetcher);const client=new ApiClient('/api');expect((await client.downloadPacket('/packet')).size).toBe(40);expect(fetcher.mock.calls[0]?.[1]).toMatchObject({credentials:'same-origin'})
 })
 it('类型、长度、内容哈希、缺失浏览器验证器均阻止保存',async()=>{
  vi.stubGlobal('crypto',webcrypto)
  for(const response of [await packetResponse(bytes,{'Content-Type':'text/html'}),await packetResponse(bytes,{'Content-Length':'67108865'}),await packetResponse(bytes,{'X-Content-SHA256':'bad'}),await packetResponse(bytes.slice(1)),await packetResponse(new Uint8Array(40)),await packetResponse(new Uint8Array(41)),new Response(null,{headers:{'Content-Type':'application/x-pcapng','Content-Length':'40','X-Content-SHA256':'a'.repeat(64)}})]){vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response));await expect(new ApiClient('/api').downloadPacket('/packet')).rejects.toMatchObject({code:'invalid_packet_download'})}
  vi.stubGlobal('crypto',{});vi.stubGlobal('fetch',vi.fn().mockResolvedValue(await packetResponse()));await expect(new ApiClient('/api').downloadPacket('/packet')).rejects.toMatchObject({code:'packet_verification_unavailable'})
 })
 it('登录失效、迟到结果和取消保持原有会话语义',async()=>{
  vi.stubGlobal('crypto',webcrypto);const unauthorized=vi.fn(),client=new ApiClient('/api');client.onUnauthorized=unauthorized
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{}',{status:401})));await expect(client.downloadPacket('/packet')).rejects.toMatchObject({status:401});expect(unauthorized).toHaveBeenCalledOnce()
  const wait=deferred<Response>();vi.stubGlobal('fetch',vi.fn().mockImplementation(()=>wait.promise));const pending=client.downloadPacket('/packet');client.setCSRF('new-session');wait.resolve(await packetResponse());await expect(pending).rejects.toMatchObject({code:'session_changed'})
  const controller=new AbortController();controller.abort();vi.stubGlobal('fetch',vi.fn().mockResolvedValue(await packetResponse()));await expect(client.downloadPacket('/packet',controller.signal)).rejects.toMatchObject({name:'AbortError'})
 })
 it('提交明确导出范围与 CSRF，不能接收被静默降级的文件',async()=>{
  vi.stubGlobal('crypto',webcrypto);const client=new ApiClient('/api');client.setCSRF('csrf-owned');const fetcher=vi.fn().mockResolvedValue(await packetResponse(bytes,{'X-Session-Completeness':'full_session'}));vi.stubGlobal('fetch',fetcher)
  expect((await client.downloadPacket('/packet-archives/session-export',undefined,exportRequest)).size).toBe(40);expect(fetcher.mock.calls[0]?.[1]).toMatchObject({method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':'csrf-owned'},body:JSON.stringify(exportRequest)})
  fetcher.mockResolvedValueOnce(await packetResponse(bytes,{'X-Session-Completeness':'snapshot'}));await expect(client.downloadPacket('/export',undefined,exportRequest)).rejects.toMatchObject({code:'invalid_session_export'})
  fetcher.mockResolvedValueOnce(new Response(JSON.stringify({code:'session_incomplete',message:'握手尚未核实',report:exportReport}),{status:422}));await expect(client.downloadPacket('/export',undefined,exportRequest)).rejects.toBeInstanceOf(SessionExportError)
  fetcher.mockResolvedValueOnce(new Response(JSON.stringify({code:'session_incomplete',report:{...exportReport,packets:-1}}),{status:422}));await expect(client.downloadPacket('/export',undefined,exportRequest)).rejects.not.toBeInstanceOf(SessionExportError)
 })
})

describe('会话导出交互',()=>{
 async function fillExport(){
  const wrapper=new DOMWrapper(document.body)
  for(const [name,value] of [['连接发起端 IP','192.0.2.10'],['连接发起端端口','40000'],['服务端 IP','198.51.100.20'],['服务端端口','80'],['连接发起端 MAC','02:00:00:00:00:01'],['服务端 MAC','02:00:00:00:00:02']])await wrapper.get(`input[aria-label="${name}"]`).setValue(value)
  await flushPromises()
 }
 it('目录选择与查看分离，刷新后清除旧对象范围',async()=>{
  const wrapper=mount(PacketWorkspace,{props:{api},global,attachTo:document.body});await flushPromises();expect(button('会话导出').disabled).toBe(true)
  await wrapper.get('tbody input[type="checkbox"]').setValue(true);await click('会话导出（1）');expect(document.body.textContent).toContain('完整会话需核实真实握手');expect(document.body.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0)
  wrapper.getComponent(SessionExportDialog).vm.$emit('close');await flushPromises();await click('刷新原包');expect(button('会话导出').disabled).toBe(true)
 })
 it('条件、端口、MAC 与 VLAN 不足时无法导出',async()=>{
  const wrapper=mount(SessionExportDialog,{props:{api,archives:[record],open:true},global,attachTo:document.body});await flushPromises();expect(button('验证并导出').disabled).toBe(true);await fillExport();expect(button('验证并导出').disabled).toBe(false)
  await new DOMWrapper(document.body).get('input[aria-label="会话 VLAN 标识"]').setValue('1,,2');expect(button('验证并导出').disabled).toBe(true);await new DOMWrapper(document.body).get('input[aria-label="会话 VLAN 标识"]').setValue('4096');expect(button('验证并导出').disabled).toBe(true);await new DOMWrapper(document.body).get('input[aria-label="会话 VLAN 标识"]').setValue('1,2');expect(button('验证并导出').disabled).toBe(false)
  await wrapper.setProps({archives:[]});expect(button('验证并导出').disabled).toBe(true);expect(downloadPacket).not.toHaveBeenCalled()
 })
 it('严格失败显示具体缺口，只有明确选择快照才改变模式',async()=>{
  const wrapper=mount(SessionExportDialog,{props:{api,archives:[record],open:true},global,attachTo:document.body});await flushPromises();await fillExport();downloadPacket.mockRejectedValueOnce(new SessionExportError('完整会话条件不足',exportReport));await click('验证并导出');expect(document.body.textContent).toContain('没有核实真实的三次握手');expect(document.body.textContent).toContain('载荷序列存在缺口');expect(downloadPacket.mock.lastCall?.[2].mode).toBe('full_session')
  await new DOMWrapper(document.body).get('input[value="snapshot"]').setValue(true);downloadPacket.mockRejectedValueOnce('network');await click('验证并导出');expect(downloadPacket.mock.lastCall?.[2].mode).toBe('snapshot');expect(document.body.textContent).toContain('会话导出失败，请稍后重试')
 })
 it('取消或卸载中止当前请求，迟到内容不会保存',async()=>{
  const save=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});const wrapper=mount(SessionExportDialog,{props:{api,archives:[record],open:true},global,attachTo:document.body});await flushPromises();await fillExport();const wait=deferred<Blob>();downloadPacket.mockImplementationOnce(()=>wait.promise);await click('验证并导出');const signal=downloadPacket.mock.lastCall?.[1] as AbortSignal;expect(button('验证并导出').disabled).toBe(true);await click('取消导出');expect(signal.aborted).toBe(true);wait.resolve(new Blob(['late']));await flushPromises();expect(save).not.toHaveBeenCalled();expect(wrapper.emitted('close')).toHaveLength(1)
  const later=deferred<Blob>();downloadPacket.mockImplementationOnce(()=>later.promise);await click('验证并导出');const lastSignal=downloadPacket.mock.lastCall?.[1] as AbortSignal;wrapper.unmount();expect(lastSignal.aborted).toBe(true);later.resolve(new Blob(['later']));await flushPromises();expect(save).not.toHaveBeenCalled()
 })
 it('成功内容只保存一次并释放浏览器对象，重新打开恢复严格模式',async()=>{
  vi.useFakeTimers();const create=vi.fn(()=> 'blob:session'),revoke=vi.fn();vi.stubGlobal('URL',Object.assign(class extends URL {},{createObjectURL:create,revokeObjectURL:revoke}));const save=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{})
  const wrapper=mount(SessionExportDialog,{props:{api,archives:[record],open:true},global,attachTo:document.body});await flushPromises();await fillExport();await new DOMWrapper(document.body).get('input[value="snapshot"]').setValue(true);downloadPacket.mockResolvedValueOnce(new Blob(['verified frames']));await click('验证并导出');expect(save).toHaveBeenCalledOnce();expect(document.body.textContent).toContain('会话快照已通过 SHA-256 校验');await vi.advanceTimersByTimeAsync(1000);expect(revoke).toHaveBeenCalledWith('blob:session')
  await wrapper.setProps({open:false});await wrapper.setProps({open:true});expect((new DOMWrapper(document.body).get('input[value="full_session"]').element as HTMLInputElement).checked).toBe(true);expect((new DOMWrapper(document.body).get('input[aria-label="连接发起端 IP"]').element as HTMLInputElement).value).toBe('');expect(button('验证并导出').disabled).toBe(true)
 })
 it('完整性报告必须保持类型、范围与原因数量边界',()=>{
  expect(validSessionReport(exportReport)).toBe(true);for(const value of [null,{}, {...exportReport,packets:-1},{...exportReport,packet_bytes:65<<20},{...exportReport,reasons:Array(33).fill('gap')},{...exportReport,reasons:['<script>']},{...exportReport,first_packet_at:'invalid'}])expect(validSessionReport(value)).toBe(false)
 })
})
