import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {readDiscovery,discoveryCount,discoveryEndpoint,type DiscoveryQuery,type DiscoveryResult} from '../packages/shared/src/discovery'
import DiscoveryPanel from '../packages/shared/src/components/DiscoveryPanel.vue'
import DiscoveryWorkspace from '../platform/src/features/inventory/DiscoveryWorkspace.vue'
import InventoryForm from '../platform/src/features/inventory/InventoryForm.vue'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
const global={plugins:[registerAnt]}
const query:DiscoveryQuery={network_id:'network_owned',network_revision:1,sensor_id:'probe_owned',registration_id:'reg_owned',prefix:'192.0.2.0/24',start:'2026-10-18T00:00:00.000Z',end:'2026-10-18T01:00:00.000Z'}
const network={id:query.network_id,kind:'networks',revision:1,data:{name:'办公网段',prefix:query.prefix,network_domain:'office',active:true},created_at:query.start,updated_at:query.start}
const sensor={id:query.sensor_id,name:'办公探针',registration_id:query.registration_id,active:true,status:'online',health:{}}
function fixture(q=query):DiscoveryResult{
 const sample={event_id:'event_owned',timestamp:new Date(q.start).toISOString().replace('.000Z','.000000001Z'),observed_at:q.end,generation_id:'generation_owned',sequence:'18446744073709551615',raw_sha256:'a'.repeat(64),flow_id:'18446744073709551615',side:'source' as const,source:{ip:'192.0.2.10',port:1234,mac:'02:00:00:00:00:01'},destination:{ip:'198.51.100.20',port:443,mac:'02:00:00:00:00:02'}}
 return {schema_version:'1.0',query:q,scope:{network_id:q.network_id,network_revision:q.network_revision,network_name:'办公网段',network_domain:'office',network_prefix:q.prefix,sensor_id:q.sensor_id,sensor_name:'办公探针',registration_id:q.registration_id},queried_at:q.end,source_excluded:'0',destination_excluded:'1',partition_status:'available',addresses:[{ip:'192.0.2.10',source_records:'9007199254740993',destination_records:'0',first:sample,last:{...sample,event_id:'event_last',timestamp:new Date(q.start).toISOString().replace('.000Z','.000000002Z')}}]}
}
beforeEach(()=>{request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/sensors')?{items:[sensor],next_cursor:''}:{items:[network],next_cursor:''}))})

describe('资产观测回执',()=>{
 it('IPv6 端点加方括号，缺少地址和端口明确呈现',()=>{expect(discoveryEndpoint({ip:'2001:db8::1',port:443})).toBe('[2001:db8::1]:443');expect(discoveryEndpoint({})).toBe('未记录:未记录')})
 it('冻结范围并保留纳秒、uint64 流标识和超安全整数计数',()=>{const original=fixture(),result=readDiscovery(original,query);expect(result).toEqual(original);expect(result).not.toBe(original);expect(discoveryCount(result.addresses[0]!.source_records)).toBe('9,007,199,254,740,993')})
 it('Go 的零毫秒省略与等价时区格式不改变冻结范围，纳秒变化仍拒绝',()=>{const response=fixture();response.query={...query,start:'2026-10-18T08:00:00+08:00',end:'2026-10-18T01:00:00Z'};expect(readDiscovery(response,query).addresses).toHaveLength(1);response.query.start='2026-10-18T00:00:00.000000001Z';expect(()=>readDiscovery(response,query)).toThrow();expect(()=>readDiscovery(fixture(),{...query,end:'invalid'})).toThrow()})
 it.each([
  ['schema',(v:DiscoveryResult)=>{v.schema_version='2.0' as '1.0'}],['scope',(v:DiscoveryResult)=>{v.scope.registration_id='reg_other'}],['query',(v:DiscoveryResult)=>{v.query={...v.query,sensor_id:'probe_other'}}],['count',(v:DiscoveryResult)=>{v.source_excluded='01'}],['limit',(v:DiscoveryResult)=>{v.addresses=Array.from({length:513},()=>v.addresses[0]!)}],['duplicate',(v:DiscoveryResult)=>{v.addresses.push(v.addresses[0]!)}],['zero',(v:DiscoveryResult)=>{v.addresses[0]!.source_records='0'}],['hash',(v:DiscoveryResult)=>{v.addresses[0]!.first.raw_sha256='bad'}],['id',(v:DiscoveryResult)=>{v.addresses[0]!.first.flow_id='18446744073709551616'}],['time',(v:DiscoveryResult)=>{v.addresses[0]!.first.timestamp=query.end}],['observed',(v:DiscoveryResult)=>{v.addresses[0]!.first.observed_at='invalid'}],['port',(v:DiscoveryResult)=>{v.addresses[0]!.first.source.port=65536}],['mac',(v:DiscoveryResult)=>{v.addresses[0]!.first.source.mac='AA-BB-CC-DD-EE-FF'}],['endpoint',(v:DiscoveryResult)=>{v.addresses[0]!.first.source.ip='192.0.2.11'}],['reverse',(v:DiscoveryResult)=>{v.addresses[0]!.last.timestamp=query.start}],['direction',(v:DiscoveryResult)=>{v.addresses[0]!.last.side='destination';v.addresses[0]!.last.destination.ip='192.0.2.10'}],['absent',(v:DiscoveryResult)=>{v.partition_status='absent'}],
 ] as const)('拒绝不完整或范围不一致的 %s 回执',(_name,change)=>{const value=fixture();change(value);expect(()=>readDiscovery(value,query)).toThrow()})
 it('无分区只交付明确的空观测',()=>{expect(readDiscovery({...fixture(),addresses:[],source_excluded:'0',destination_excluded:'0',partition_status:'absent'},query).addresses).toHaveLength(0);expect(()=>readDiscovery(null,query)).toThrow()})
})

describe('被动发现列表和证据',()=>{
 it('只显示一个业务表格，证据保留端点 MAC 且登记必须由用户触发',async()=>{
  const result=fixture(),wrapper=mount(DiscoveryPanel,{props:{result,pending:false,error:'',attempted:true,canRegister:true},global,attachTo:document.body})
  expect(wrapper.findAll('.ant-table-wrapper')).toHaveLength(1);expect(wrapper.text()).toContain('9,007,199,254,740,993');expect(wrapper.emitted('register')).toBeUndefined()
  await wrapper.findAll('button').find(button=>button.text()==='证据')!.trigger('click');await flushPromises();expect(document.body.textContent).toContain('02:00:00:00:00:01');expect(document.body.textContent).toContain('采集器读取时间');expect(document.body.textContent).toContain('不能据此认定资产身份');expect(document.body.textContent).toContain('18446744073709551615')
  const buttons=Array.from(document.body.querySelectorAll<HTMLButtonElement>('.ant-modal button'));buttons.find(button=>button.textContent==='登记资产')!.click();await flushPromises();expect(wrapper.emitted('register')![0]![0]).toEqual(result.addresses[0]);expect(document.body.querySelector('.ant-modal')).toBeNull()
  await wrapper.setProps({result:null,attempted:false});expect(wrapper.text()).toContain('选择探针');await wrapper.setProps({error:'分片失败',attempted:true});expect(wrapper.text()).toContain('分片失败');await wrapper.get('button').trigger('click');expect(wrapper.emitted('retry')).toHaveLength(1)
  await wrapper.setProps({error:'',result:{...result,addresses:[],partition_status:'absent'}});expect(wrapper.text()).toContain('尚无可查询的流量分区');await wrapper.setProps({pending:true});expect(wrapper.text()).toContain('正在读取')
 })
})

async function selectScope(wrapper:ReturnType<typeof mount>){await flushPromises();const selects=wrapper.findAllComponents(Select);selects[0]!.vm.$emit('update:value',sensor.id);selects[1]!.vm.$emit('update:value',network.id);await flushPromises();await wrapper.get('#discovery-start').setValue('2026-10-18T08:00:00');await wrapper.get('#discovery-end').setValue('2026-10-18T09:00:00')}
async function submit(wrapper:ReturnType<typeof mount>){await wrapper.get('form').trigger('submit');await flushPromises()}
describe('发现查询与资产登记',()=>{
 it('完整分页目录可执行真实请求结构，成功回执与变化后的条件相隔离',async()=>{
  const second={...network,id:'network_second',data:{...network.data,name:'其他网段'}}
  request.mockImplementation((path:string,options?:{body:DiscoveryQuery})=>Promise.resolve(path.startsWith('/sensors')?{items:[sensor],next_cursor:''}:path==='/inventory/discovery'?fixture(options!.body):path.includes('cursor=network_owned')?{items:[second],next_cursor:''}:{items:[network],next_cursor:network.id}))
  const wrapper=mount(DiscoveryWorkspace,{global,attachTo:document.body});await selectScope(wrapper);expect(wrapper.text()).toContain('2 个使用中网段');await submit(wrapper);expect(wrapper.findComponent(DiscoveryPanel).props('result')?.addresses).toHaveLength(1)
  await wrapper.get('#discovery-prefix').setValue('192.0.2.0/25');expect(wrapper.findComponent(DiscoveryPanel).props('result')).toBeNull();const requests=request.mock.calls;wrapper.unmount();expect((requests[0]![1].signal as AbortSignal).aborted).toBe(true)
 })
 it('校验查询、按当前目录冻结范围，改变条件立即取消旧请求',async()=>{
  const wrapper=mount(DiscoveryWorkspace,{global,attachTo:document.body});await flushPromises();await submit(wrapper);expect(wrapper.text()).toContain('请选择探针')
  await selectScope(wrapper);let resolve!:(v:unknown)=>void
  request.mockImplementation((path:string)=>path==='/inventory/discovery'?new Promise(done=>{resolve=done}):Promise.resolve({items:[],next_cursor:''}))
  await submit(wrapper);const call=request.mock.calls.find(call=>call[0]==='/inventory/discovery')!;expect(call[1].body).toMatchObject({sensor_id:sensor.id,network_id:network.id,registration_id:sensor.registration_id,network_revision:1});expect(wrapper.text()).toContain('取消查询')
  await wrapper.get('#discovery-prefix').setValue('192.0.2.0/25');expect(call[1].signal.aborted).toBe(true);resolve(fixture(call[1].body));await flushPromises();expect(wrapper.text()).not.toContain('9,007,199');expect(wrapper.findComponent(DiscoveryPanel).props('result')).toBeNull()
  await wrapper.get('#discovery-end').setValue('2026-10-20T09:00:00');await submit(wrapper);expect(wrapper.text()).toContain('不超过 24 小时');wrapper.unmount()
 })
 it('请求失败、取消与目录失效不展示旧数据，允许刷新',async()=>{
  const wrapper=mount(DiscoveryWorkspace,{global,attachTo:document.body});await selectScope(wrapper);request.mockRejectedValueOnce(new Error('网段修订已变化'));await submit(wrapper);expect(wrapper.text()).toContain('网段修订已变化')
  request.mockImplementation(()=>new Promise(()=>{}));await submit(wrapper);const call=request.mock.lastCall!;await wrapper.findAll('button').find(button=>button.text()==='取消查询')!.trigger('click');expect(call[1].signal.aborted).toBe(true);expect(wrapper.text()).toContain('查询已取消')
  request.mockRejectedValue(new Error('目录读取失败'));await wrapper.findAll('button').find(button=>button.text()==='刷新目录')!.trigger('click');await flushPromises();expect(wrapper.text()).toContain('目录读取失败');expect(wrapper.findComponent(DiscoveryPanel).props('result')).toBeNull();wrapper.unmount()
 })
 it('从观测登记仅预填 IP 和网络域，保存失败保留稳定表单',async()=>{
  const wrapper=mount(DiscoveryWorkspace,{global,attachTo:document.body});await flushPromises()
  wrapper.findComponent(DiscoveryPanel).vm.$emit('register',fixture().addresses[0],fixture());await flushPromises()
  const editor=wrapper.findComponent(InventoryForm);expect(editor.props('draft')).toMatchObject({name:'',network_domain:'office',interfaces:[{name:'',mac:'',ips:['192.0.2.10']}]});expect(request.mock.calls.some(call=>call[0]==='/inventory/assets')).toBe(false)
  request.mockRejectedValueOnce(new Error('修订冲突'));editor.vm.$emit('save',{name:'已确认资产'},'asset_stable');await flushPromises();expect(editor.props('error')).toBe('修订冲突');expect(wrapper.findComponent(InventoryForm).exists()).toBe(true)
  request.mockResolvedValueOnce({});editor.vm.$emit('save',{name:'已确认资产'},'asset_stable');await flushPromises();expect(wrapper.text()).toContain('已登记');expect(wrapper.findComponent(InventoryForm).exists()).toBe(false);expect(request.mock.lastCall?.[1].body).toMatchObject({id:'asset_stable',expected_revision:0});wrapper.unmount()
 })
 it('拒绝未结束或重复的网段目录，不把第一页当成完整范围',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/sensors')?{items:[sensor],next_cursor:''}:{items:[network],next_cursor:network.id}))
  const wrapper=mount(DiscoveryWorkspace,{global});await flushPromises();expect(wrapper.text()).toContain('不完整');expect(wrapper.findAllComponents(Select)[1]!.props('options')).toEqual([]);wrapper.unmount()
 })
 it('任一目录失败立即取消另一目录，不继续后台分页',async()=>{
  let signal:AbortSignal|undefined
  request.mockImplementation((path:string,options:{signal:AbortSignal})=>path.startsWith('/sensors')?Promise.reject(new Error('探针目录不可用')):new Promise((_resolve,reject)=>{signal=options.signal;signal.addEventListener('abort',()=>reject(new Error('读取取消')))}))
  const wrapper=mount(DiscoveryWorkspace,{global});await flushPromises();expect(signal?.aborted).toBe(true);expect(wrapper.text()).toContain('探针目录不可用');wrapper.unmount()
 })
})
