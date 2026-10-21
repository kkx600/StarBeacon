import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {shallowRef} from 'vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiClient} from '../packages/shared/src/api'
import {emptySourceQuery,sourceQuery,readSources,readSourcePage,emptyLogQuery,logQuery,readLogPage,readLogDetail,type SourceQuery,type LogQuery,type LogDocument} from '../packages/shared/src/syslog'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import SyslogSources from '../packages/shared/src/components/SyslogSources.vue'
import SyslogLogs from '../packages/shared/src/components/SyslogLogs.vue'
import SyslogLogTable from '../packages/shared/src/components/SyslogLogTable.vue'
import SyslogLogDetail from '../packages/shared/src/components/SyslogLogDetail.vue'
import SyslogSourcesView from '../platform/src/views/SyslogSourcesView.vue'
import {syslogLog,syslogSource} from './syslog-fixture'
import {click,deferred,principal} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef({id:'admin_example',tenant_id:'tenant_example',role:'admin'})}}))
const wrappers:VueWrapper[]=[],global={plugins:[registerAnt]},api={request} as unknown as ApiClient
function attach(component:any,props:Record<string,unknown>={}){const w=mount(component,{props,global,attachTo:document.body});wrappers.push(w);return w}
function logDocument(raw=false):LogDocument{const row=structuredClone(syslogLog);row.received_at=new Date(Date.now()-1000).toISOString();if(!raw){delete row.record.raw_base64;delete row.parsed.structured_data};return row}
function goTime(value:string){return value.replace(/\.000Z$/,'Z').replace(/(\.\d*?[1-9])0+Z$/,'$1Z')}
function page(q:LogQuery,items:LogDocument[]=[]){return {items,query:{...q,start:goTime(q.start),end:goTime(q.end)},next_cursor:''}}
function sourcePage(q:SourceQuery,items=[syslogSource()]){return {items,query:{...q},next_cursor:'',observed_at:new Date().toISOString()}}
function query(path:string):SourceQuery{return Object.fromEntries([...new URLSearchParams(path.split('?')[1])].map(([k,v])=>[k,k==='limit'?Number(v):v])) as unknown as SourceQuery}
beforeEach(()=>{request.mockReset()})
afterEach(()=>{wrappers.splice(0).forEach(w=>w.unmount());window.document.body.innerHTML='';vi.useRealTimers()})

describe('Syslog 来源与检索',()=>{
 it('来源边界、分页回显与重复身份拒绝',()=>{
  const q=emptySourceQuery(),row=syslogSource();expect(sourceQuery(q)).toEqual(q);expect(readSourcePage(sourcePage(q),q).items).toHaveLength(1);expect(readSources([])).toEqual([])
  for(const change of [{limit:0},{limit:101},{sensor_id:'UPPER'},{source_id:'bad/id'}])expect(()=>sourceQuery({...q,...change})).toThrow()
  for(const value of [null,{},[row,row],[{...row,source_id:'UPPER'}],[{...row,state:'unknown'}],[{...row,observed_at:'bad'}],[{...row,persisted:'01'}],[{...row,max_message_bytes:1}],[{...row,registration_id:'UPPER'}]])expect(()=>readSources(value)).toThrow()
  for(const value of [null,{...sourcePage(q),query:{...q,limit:1}},{...sourcePage(q),next_cursor:'bad!'},{...sourcePage(q),observed_at:'bad'}])expect(()=>readSourcePage(value,q)).toThrow()
  expect(()=>readSourcePage(sourcePage({...q,limit:1},[row,row]),{...q,limit:1})).toThrow();expect(()=>readSourcePage(sourcePage({...q,sensor_id:'other'}),{...q,sensor_id:'other'})).toThrow()
 })
 it('日志过滤时间、文本与分级约束',()=>{
  const q=emptyLogQuery();expect(logQuery(q)).toEqual(q)
  for(const change of [{start:'bad'},{end:q.start},{start:new Date(Date.now()-32*86400000).toISOString()},{sensor_id:'UPPER'},{state:'success'},{severity:8},{keyword:'bad\ntext'},{application:'x'.repeat(257)},{peer_ip:'x'.repeat(46)},{limit:101}])expect(()=>logQuery({...q,...change})).toThrow()
  const row=logDocument(),result=page(q,[row]);expect(readLogPage(result,q,'tenant_example').items).toHaveLength(1)
  for(const value of [null,{...result,query:{...q,limit:2}},{...result,next_cursor:'bad!'},page(q,[row,row]),page(q,[{...row,tenant_id:'other'}]),page(q,[logDocument(true)]),page(q,[{...row,event_id:'bad'}]),page(q,[{...row,received_at:new Date(Date.now()+86400000).toISOString()}])])expect(()=>readLogPage(value,q,'tenant_example')).toThrow()
  expect(()=>readLogPage(page({...q,source_id:'other'},[row]),{...q,source_id:'other'},'tenant_example')).toThrow()
 })
 it('查询回显按纳秒时刻核对，兼容 Go 省略小数秒尾零但拒绝改变时间边界',()=>{
  const q={...emptyLogQuery(),start:'2026-10-21T00:00:00.000Z',end:'2026-10-21T01:00:00.010Z'},response={items:[],query:{...q,start:'2026-10-21T00:00:00Z',end:'2026-10-21T01:00:00.01Z'},next_cursor:''}
  expect(readLogPage(response,q,'tenant_example').items).toEqual([])
  for(const end of ['2026-10-21T01:00:00.010000001Z','2026-10-21T01:00:00.009999999Z','invalid'])expect(()=>readLogPage({...response,query:{...response.query,end}},q,'tenant_example')).toThrow('当前查询不一致')
  expect(()=>readLogPage({...response,query:{...response.query,source_id:'other'}},q,'tenant_example')).toThrow('当前查询不一致')
 })
 it('原文与外层载荷摘要均验证，阻止错误对象及损坏字节',async()=>{
  const row=structuredClone(syslogLog);expect((await readLogDetail(row,'tenant_example',row.event_id,row.partition)).record.raw_base64).toBeTruthy();expect(await goJSONDigest(row.record)).toBe(row.payload_sha256)
  for(const change of [{event_id:'e'.repeat(64)},{partition:'2026-10-20'},{payload_sha256:'e'.repeat(64)},{record:{...row.record,raw_sha256:'e'.repeat(64)}},{record:{...row.record,raw_base64:'@@'}},{record:{...row.record,raw_base64:''}}])await expect(readLogDetail({...row,...change},'tenant_example',row.event_id,row.partition)).rejects.toThrow()
 })
 it('来源表格单表、详情、状态和自然老化一致',async()=>{
  const row=syslogSource(),w=attach(SyslogSources,{items:[row]});expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);expect(w.text()).toContain('正在接收');await click('查看');await flushPromises();expect(window.document.body.textContent).toContain('客户端证书与指纹验证');expect(window.document.querySelector('.ant-modal-footer button')?.textContent?.replace(/\s/g,'')).toBe('关闭');await click('关闭');await flushPromises();expect(w.emitted('close')).toHaveLength(1)
  for(const [change,label] of [[{sensor_status:'disabled'},'探针已停用'],[{sensor_status:'offline'},'探针离线'],[{observation:'stale'},'观测已过期'],[{state:'unavailable'},'监听不可用'],[{state:'degraded'},'持久缓冲不可用']] as const){await w.setProps({items:[{...row,...change}]});expect(w.text()).toContain(label)}
  await w.setProps({items:[{...row,transport:'udp',identity_quality:'network_allowlist',upstream_loss:'unmeasurable',format:'rfc3164',timezone:'Asia/Shanghai'}],local:true,detailID:row.source_id});await flushPromises();expect(window.document.body.textContent).toContain('无法据此推算发送侧丢失率');expect(window.document.body.textContent).toContain('Asia/Shanghai')
  await w.setProps({items:[]});await flushPromises();expect(w.text()).not.toContain('边界设备日志')
 })
 it('实际来源目录支持筛选、失败保留旧数据、清空与卸载取消',async()=>{
  request.mockImplementation(async(path:string)=>sourcePage(query(path)));const w=attach(SyslogSourcesView);await vi.waitFor(()=>expect(w.text()).toContain('边界设备日志'));expect(w.get('h1').text()).toBe('Syslog 接收')
  request.mockRejectedValueOnce(new Error('目录连接中断'));await click('刷新来源');await vi.waitFor(()=>expect(w.text()).toContain('目录连接中断'));expect(w.text()).toContain('边界设备日志')
  await w.get('[aria-label="Syslog 来源标识"]').setValue('UPPER');const calls=request.mock.calls.length;await click('查询');expect(request).toHaveBeenCalledTimes(calls);expect(w.text()).toContain('1–64 位')
  request.mockImplementation(async(path:string)=>sourcePage(query(path),[]));await click('重置');await vi.waitFor(()=>expect(w.text()).toContain('当前条件下没有 Syslog 来源'))
  const blocked=deferred<unknown>();request.mockReturnValueOnce(blocked.promise);await click('刷新来源');const signal=request.mock.lastCall?.[1].signal;w.unmount();expect(signal.aborted).toBe(true);blocked.reject(new Error('取消'));await flushPromises()
 })
 it('日志工作台保持单表，原文单独请求并在关闭时取消',async()=>{
  const row=logDocument();request.mockImplementation(async(path:string,options:any)=>path==='/logs/search'?page(options.body,[row]):syslogLog)
  const w=attach(SyslogLogs,{api,principal:{...principal,tenant_id:'tenant_example'}});await vi.waitFor(()=>expect(w.text()).toContain('访问策略拒绝'));expect(w.findAll('.ant-table-wrapper')).toHaveLength(1)
  w.getComponent(SyslogLogTable).vm.$emit('view',row);await vi.waitFor(()=>expect(window.document.body.textContent).toContain('Syslog 原始消息字节'));expect(request.mock.lastCall?.[0]).toContain(`/logs/${row.event_id}?partition=${row.partition}`)
  expect(window.document.querySelector('.ant-modal-footer button')?.textContent?.replace(/\s/g,'')).toBe('关闭');await click('关闭');await flushPromises();expect(w.getComponent(SyslogLogDetail).props('open')).toBe(false)
  const blocked=deferred<unknown>();request.mockReturnValueOnce(blocked.promise);w.getComponent(SyslogLogTable).vm.$emit('view',row);await flushPromises();const signal=request.mock.lastCall?.[1].signal;w.getComponent(SyslogLogDetail).vm.$emit('close');expect(signal.aborted).toBe(true);blocked.resolve(syslogLog);await flushPromises();expect(w.getComponent(SyslogLogDetail).props('document')).toBe(null)
 })
 it('原文加载失败可重试，检索错误、空条件和文本验证可恢复',async()=>{
  const row=logDocument();request.mockImplementation(async(path:string,options:any)=>path==='/logs/search'?page(options.body,[row]):Promise.reject(new Error('原文读取失败')))
  const w=attach(SyslogLogs,{api,principal:{...principal,tenant_id:'tenant_example'}});await vi.waitFor(()=>expect(w.text()).toContain('访问策略拒绝'));w.getComponent(SyslogLogTable).vm.$emit('view',row);await vi.waitFor(()=>expect(window.document.body.textContent).toContain('原文读取失败'));request.mockResolvedValueOnce(syslogLog);w.getComponent(SyslogLogDetail).vm.$emit('retry');await vi.waitFor(()=>expect(window.document.body.textContent).toContain('原文 SHA-256'))
  w.getComponent(SyslogLogDetail).vm.$emit('close');await w.get('[aria-label="日志探针"]').setValue('UPPER');const before=request.mock.calls.length;await click('查询');expect(request).toHaveBeenCalledTimes(before);expect(w.text()).toContain('31 天')
  request.mockImplementation(async(_path:string,options:any)=>page(options.body));await click('重置');await vi.waitFor(()=>expect(w.text()).toContain('当前条件下没有日志记录'))
  request.mockRejectedValueOnce(new Error('检索连接中断'));await click('刷新结果');await vi.waitFor(()=>expect(w.text()).toContain('检索连接中断'))
 })
 it('合成原型空、加载、错误、详情和字节展示与工程组件一致',async()=>{
  const w=attach(SyslogLogs,{preview:[syslogLog],state:'detail'});await flushPromises();expect(window.document.body.textContent).toContain('Syslog 原始消息字节');w.getComponent(SyslogLogDetail).vm.$emit('close');expect(w.emitted('state')).toContainEqual(['data'])
  for(const state of ['empty','loading','error','data']){await w.setProps({state});await flushPromises();expect(w.findAll('.ant-table-wrapper')).toHaveLength(state==='data'?1:0)}
  await click('查询');expect(w.emitted('state')).toContainEqual(['data']);await click('重置');await flushPromises();expect(w.getComponent(SyslogLogTable).props('items')).toHaveLength(1)
 })
})
