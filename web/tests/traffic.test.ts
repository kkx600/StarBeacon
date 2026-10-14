import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {Select,Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal} from '../packages/shared/src/types'
import TrafficWorkspace from '../platform/src/features/traffic/TrafficEvents.vue'
import TrafficFilters from '../platform/src/features/traffic/TrafficFilters.vue'
import TrafficDetail from '../platform/src/features/traffic/TrafficDetail.vue'
import TrafficTable from '../platform/src/features/traffic/TrafficTable.vue'
import {defaultTrafficFilters,endpoint,validTrafficResult,type TrafficQuery,type TrafficRecord,type TrafficResult} from '../platform/src/features/traffic/traffic'
import {useTraffic} from '../platform/src/features/traffic/useTraffic'
import {session} from '../platform/src/session'
import {principal,click,button,deferred} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]},query:TrafficQuery={...defaultTrafficFilters(),start:'2026-10-03T00:00:00Z',end:'2026-10-04T00:00:00Z',page:1,page_size:20}
function record(q:TrafficQuery=query):TrafficRecord{return{event_id:'flow_owned',tenant_id:principal.tenant_id,sensor_id:'sensor_owned',sensor_registration_id:'reg_owned',source_generation_id:'gen_owned','@timestamp':new Date(Date.parse(q.start)+1000).toISOString(),observed_at:'2026-10-03T01:00:00Z',received_at:'2026-10-03T01:00:01Z',raw_sha256:'a'.repeat(64),source_offset:'0',sequence:'1',source:{ip:'2001:db8::1',port:443,mac:'02:00:00:00:00:01'},destination:{ip:'192.0.2.1',port:8080},network:{protocol:'http',transport:'tcp'},http:{method:'GET',hostname:'service.test',path:'/api'},suricata:{flow_id:'18446744073709551615'},rule:{},severity:'unknown',event:{kind:q.event_kind||'flow',original:'{"event_type":"flow"}'},evidence_status:'unavailable',details:{state:'available',truncated:false,source_macs:['02:00:00:00:00:01'],destination_macs:['02:00:00:00:00:02'],community_id:'1:observed',packet_source:'wire/pcap',direction:'to_server',flow:{start:'2026-10-03T01:00:00Z',end:'2026-10-03T01:00:01Z',state:'closed',reason:'shutdown',packets_to_server:'9',packets_to_client:'0',bytes_to_server:'18446744073709551615',bytes_to_client:'0'},tls:null,dns:null}}}
function result(q:TrafficQuery=query):TrafficResult{return{items:[record(q)],total:1,page:q.page,page_size:q.page_size}}
beforeEach(()=>{(session.current as ShallowRef<Principal|null>).value=principal;request.mockReset();request.mockImplementation((path:string,options?:{body?:TrafficQuery})=>Promise.resolve(path==='/traffic/search'?result(options!.body!):path==='/search/validate'?{valid:true}:{fields:[{name:'http.path',label:'HTTP 路径',type:'string',aliases:['http.request.uri'],operators:['contains']},{name:'tcp',label:'TCP',type:'protocol',aliases:[],operators:[]}]}))})

describe('流量响应契约',()=>{
 it('协议事务缺失包数保持缺测，会话零包不显示为缺测',async()=>{
  const missing=result();missing.items[0]!.event.kind='http';missing.items[0]!.details.flow=null
  const wrapper=mount(TrafficTable,{props:{result:missing},global,attachTo:document.body});await flushPromises()
  expect(wrapper.text()).toContain('包数未获取');expect(wrapper.text()).not.toContain('未获取 包');expect(wrapper.text()).not.toContain('0 B')
  const counted=result();counted.items[0]!.details.flow!.packets_to_server='0';await wrapper.setProps({result:counted});expect(wrapper.text()).toContain('0 包');expect(wrapper.text()).not.toContain('包数未获取');wrapper.unmount()
  const detail=mount(TrafficDetail,{props:{record:missing.items[0]!},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('包数未获取');expect(document.body.textContent).not.toContain('未获取 包');detail.unmount()
 })
 it('计数保留 uint64 精度，IPv6 端口与缺测含义清楚',()=>{
  expect(validTrafficResult(result(),query,principal.tenant_id)).toBe(true)
  expect(endpoint('2001:db8::1',443)).toBe('[2001:db8::1]:443');expect(endpoint('192.0.2.1',80)).toBe('192.0.2.1:80');expect(endpoint('2001:db8::1',undefined)).toBe('2001:db8::1');expect(endpoint(undefined,80)).toBe('未观测到')
  const empty={items:[],total:0,page:1,page_size:20};expect(validTrafficResult(empty,query,principal.tenant_id)).toBe(true)
  const unavailable=result();unavailable.items[0]!.details={...record().details,state:'unavailable',flow:null,tls:null,dns:null};expect(validTrafficResult(unavailable,query,principal.tenant_id)).toBe(true)
  const missing=result();missing.items[0]!.details.flow={...record().details.flow!,start:null,end:null,packets_to_server:'',bytes_to_server:''};expect(validTrafficResult(missing,query,principal.tenant_id)).toBe(true)
 })
 it('不完整分页、跨租户记录、重复事件与超出范围不能当作检索成功',()=>{
  const mutations:Array<(v:TrafficResult)=>void>=[v=>{v.total=-1},v=>{v.total=1.1},v=>{v.total=2},v=>{v.page=2},v=>{v.page_size=50},v=>{v.items=[]},v=>{v.items[0]!.tenant_id='foreign'},v=>{v.items[0]!.event.kind='alert'},v=>{v.items[0]!['@timestamp']=query.end},v=>{v.items[0]!['@timestamp']='invalid'},v=>{v.items[0]!['@timestamp']='2026-10-02T00:00:00Z'},v=>{v.items.push(v.items[0]!);v.total=2}]
  for(const mutate of mutations){const value=result();mutate(value);expect(validTrafficResult(value,query,principal.tenant_id)).toBe(false)}
  for(const value of [null,[],{}, {...result(),items:null},{...result(),items:[null]},{...result(),items:[{...record(),source:null}]},{...result(),items:[{...record(),event:{kind:'flow',original:null}}]}])expect(validTrafficResult(value,query,principal.tenant_id)).toBe(false)
  expect(validTrafficResult(result(),{...query,event_kind:'http'},principal.tenant_id)).toBe(false)
 })
 it('协议展示拒绝不合法计数、倒置会话时间和不完整字段',()=>{
  for(const counter of ['-1','01','1.1','18446744073709551616','+1']){const value=result();value.items[0]!.details.flow!.bytes_to_server=counter;expect(validTrafficResult(value,query,principal.tenant_id)).toBe(false)}
  const shapes=[{state:'bad'},{truncated:null},{source_macs:Array(17).fill('02:00:00:00:00:01')},{destination_macs:[null]},{community_id:null},{flow:{...record().details.flow!,start:'bad'}},{flow:{...record().details.flow!,end:'2026-10-03T00:00:00Z'}},{flow:{}},{tls:{}},{dns:{}},{state:'unavailable',flow:record().details.flow}]
  for(const details of shapes)expect(validTrafficResult({...result(),items:[{...record(),details:{...record().details,...details}}]},query,principal.tenant_id)).toBe(false)
  const dns={version:'3',type:'answer',rcode:'NOERROR',queries:[{name:'service.test',type:'A'}]},tls={sni:'service.test',version:'TLS 1.3',subject:'CN=service.test',issuer:'CN=ca.test',fingerprint:'owned'}
  expect(validTrafficResult({...result(),items:[{...record(),details:{...record().details,tls,dns}}]},query,principal.tenant_id)).toBe(true)
  for(const queries of [Array(33).fill({name:'n',type:'A'}),[null],[{name:1,type:'A'}]])expect(validTrafficResult({...result(),items:[{...record(),details:{...record().details,dns:{...dns,queries}}}]},query,principal.tenant_id)).toBe(false)
 })
})

describe('流量检索页面',()=>{
 it('一张业务表格显示双向计数，详情说明实际时间、来源和原始权限',async()=>{
  const wrapper=mount(TrafficWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('流量记录');expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('[2001:db8::1]:443');expect(wrapper.text()).toContain('18.45 EB');expect(wrapper.text()).toContain('0 B');expect(wrapper.text()).toContain('记录数不等于独立会话数')
  await click('查看');expect(document.body.textContent).toContain('流量记录详情');expect(document.body.textContent).toContain('事件时间不是网络出站时间');expect(document.body.textContent).toContain('18446744073709551615');expect(document.body.textContent).toContain('reg_owned');expect(document.body.textContent).toContain('gen_owned');expect(document.body.textContent).toContain('原始 EVE');expect(document.body.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0)
  ;(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(wrapper.getComponent(TrafficDetail).props('record')).toBeNull()
 })
 it('空列表和依赖失败可区分，刷新恢复后不显示过期结果',async()=>{
  request.mockResolvedValueOnce({items:[],total:0,page:1,page_size:20});const wrapper=mount(TrafficWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('当前条件下没有协议记录');expect(wrapper.findAll('.ant-table')).toHaveLength(0)
  request.mockRejectedValueOnce(new Error('流量检索未完成'));await click('刷新');expect(wrapper.text()).toContain('流量检索未完成');expect(wrapper.text()).not.toContain('当前条件下没有协议记录');await click('重试');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  request.mockResolvedValueOnce({items:[record()],total:2,page:1,page_size:20});await click('刷新');expect(wrapper.text()).toContain('响应不完整');expect(wrapper.findAll('.ant-table')).toHaveLength(0)
 })
 it('超出一万条提示收窄范围，分页携带原窗口并限制列表',async()=>{
  request.mockImplementation((path:string,options?:{body?:TrafficQuery})=>{if(path!=='/traffic/search')return Promise.resolve({fields:[]});const q=options!.body!;return Promise.resolve({items:Array.from({length:q.page_size},(_,i)=>({...record(q),event_id:`flow_${(q.page-1)*q.page_size+i}`})),total:11000,page:q.page,page_size:q.page_size})})
  const wrapper=mount(TrafficWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('最多浏览前 10,000 条');const first=request.mock.calls[0]![1].body
  await wrapper.get('.ant-pagination-next').trigger('click');await flushPromises();const next=request.mock.calls.find(c=>c[1]?.body?.page===2)![1].body;expect(next.start).toBe(first.start);expect(next.end).toBe(first.end);expect(wrapper.findAll('.ant-table-row')).toHaveLength(20)
 })
 it('TLS、DNS、缺测和展示截断均保留明确业务解释',async()=>{
  const value=record();value.event.original='';value.source={};value.destination={};value.network={};value.http={};value.sensor_registration_id='';value.source_generation_id='';value.suricata={};value.details={...value.details,truncated:true,source_macs:[],destination_macs:[],community_id:'',direction:'',packet_source:'',flow:null,tls:{sni:'',version:'',subject:'',issuer:'',fingerprint:''},dns:{version:'3',type:'answer',rcode:'NOERROR',queries:[{name:'service.test',type:'A'}]}}
  const wrapper=mount(TrafficDetail,{props:{record:value},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('字段达到长度或数量限制');expect(document.body.textContent).toContain('不证明密文已解密');expect(document.body.textContent).toContain('service.test');expect(document.body.textContent).toContain('当前账号未获原始载荷读取权限');expect(document.body.textContent).toContain('未获取');expect(document.body.textContent).toContain('未观测到')
  await wrapper.setProps({record:{...value,details:{...value.details,state:'unavailable',truncated:false,tls:null,dns:{version:'',type:'',rcode:'',queries:[]}}}});await flushPromises();expect(document.body.textContent).toContain('无法完整解析');expect(document.body.textContent).toContain('未提供可解析的查询数组');wrapper.getComponent(Modal).vm.$emit('cancel');expect(wrapper.emitted('close')).toHaveLength(1)
 })
})

describe('流量过滤交互',()=>{
 it('协议和时间切换、源地址、流标识与高级字段使用流量目录',async()=>{
  const wrapper=mount(TrafficFilters,{props:{pending:false},global,attachTo:document.body});await wrapper.findAllComponents(Select)[0]!.setValue('http','value');await wrapper.findAllComponents(Select)[1]!.setValue(168,'value');await wrapper.get('input[aria-label="源 IP"]').setValue('2001:db8::1');await wrapper.get('input[aria-label="流标识"]').setValue('18446744073709551615');await click('高级检索');expect(request).toHaveBeenCalledWith('/traffic/fields',expect.anything());expect(wrapper.text()).toContain('作用于协议事件索引')
  await click('字段目录');expect(document.body.textContent).toContain('流量检索字段');await click('http.path');await wrapper.get('textarea').setValue('http.path contains "/api"');await wrapper.get('form').trigger('submit');await flushPromises();expect(request.mock.calls.find(c=>c[0]==='/search/validate')?.[1].body).toEqual({filter:'http.path contains "/api"'});expect(wrapper.emitted('search')?.[0]?.[1]).toBe(168);expect(wrapper.emitted('search')?.[0]?.[0]).toMatchObject({event_kind:'http',source_ip:'2001:db8::1',flow_id:'18446744073709551615'})
  await click('重置');expect(wrapper.emitted('search')?.[1]).toEqual([defaultTrafficFilters(),24]);await click('收起高级检索');expect(wrapper.find('textarea').exists()).toBe(false)
 })
 it('非法表达式和服务失败保留输入，等待、卸载不提交重复请求',async()=>{
  const wrapper=mount(TrafficFilters,{props:{pending:false},global,attachTo:document.body});await click('高级检索');await wrapper.get('textarea').setValue('tcp.port == 443');request.mockResolvedValueOnce({valid:false});await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.text()).toContain('未通过校验');expect(wrapper.emitted('search')).toBeUndefined()
  request.mockRejectedValueOnce('unavailable');await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.text()).toContain('过滤表达式校验失败');request.mockRejectedValueOnce(new Error('字段无法校验'));await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.text()).toContain('字段无法校验')
  const waiting=deferred<{valid:boolean}>();request.mockImplementationOnce(()=>waiting.promise);await wrapper.get('form').trigger('submit');await flushPromises();expect(button('重置').disabled).toBe(true);const before=request.mock.calls.length;await wrapper.get('form').trigger('submit');await flushPromises();expect(request.mock.calls).toHaveLength(before);const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);waiting.resolve({valid:true});await flushPromises();expect(wrapper.emitted('search')).toBeUndefined()
 })
 it('等待查询时禁用条件，无高级表达式可直接检索',async()=>{
  const wrapper=mount(TrafficFilters,{props:{pending:true},global,attachTo:document.body});await wrapper.get('form').trigger('submit');expect(wrapper.emitted('search')).toBeUndefined();expect(button('检索').disabled).toBe(true);await wrapper.setProps({pending:false});await wrapper.get('form').trigger('submit');await flushPromises();expect(wrapper.emitted('search')?.[0]).toEqual([defaultTrafficFilters(),24]);expect(request).not.toHaveBeenCalled()
 })
})

describe('流量请求生命周期',()=>{
 function hook(){let state!:ReturnType<typeof useTraffic>;const wrapper=mount(defineComponent({setup(){state=useTraffic();return()=>h('div')}}));return{state,wrapper}}
 it('取消迟到查询和卸载响应，分页不改变条件或时间边界',async()=>{
  const waiting=deferred<TrafficResult>();request.mockImplementationOnce(()=>waiting.promise);const {state,wrapper}=hook(),first=request.mock.calls[0]![1];state.search({...defaultTrafficFilters(),sensor_id:'selected'},168);await flushPromises();expect(first.signal.aborted).toBe(true);const completed=state.result.value;waiting.resolve(result(first.body));await flushPromises();expect(state.result.value).toBe(completed);expect(state.range.value).not.toBeNull();let q=request.mock.lastCall![1].body as TrafficQuery;expect(Date.parse(q.end)-Date.parse(q.start)).toBe(168*3600000)
  request.mockImplementationOnce((_path,options)=>Promise.resolve({items:[],total:1,page:options.body.page,page_size:options.body.page_size}));state.page(2,50);await flushPromises();let next=request.mock.lastCall![1].body;expect(next.start).toBe(q.start);expect(next.sensor_id).toBe('selected');const calls=request.mock.calls.length;for(const [page,size] of [[0,20],[1,25],[501,20],[1.5,20],[1,NaN]])state.page(page!,size!);await flushPromises();expect(request.mock.calls).toHaveLength(calls)
  state.search(defaultTrafficFilters(),720);await flushPromises();q=request.mock.lastCall![1].body;expect(Date.parse(q.end)-Date.parse(q.start)).toBe(720*3600000);state.search(defaultTrafficFilters(),999);await flushPromises();q=request.mock.lastCall![1].body;expect(Date.parse(q.end)-Date.parse(q.start)).toBe(86400000)
  const late=deferred<TrafficResult>();request.mockImplementationOnce(()=>late.promise);state.refresh();await flushPromises();next=request.mock.lastCall![1];const previous=state.result.value;wrapper.unmount();expect(next.signal.aborted).toBe(true);late.resolve(result(next.body));await flushPromises();expect(state.result.value).toBe(previous)
 })
 it('错误结果不会覆盖上次成功范围，非 Error 失败仍可理解',async()=>{
  const {state}=hook();await flushPromises();const range=state.range.value;request.mockRejectedValueOnce('offline');state.refresh();await flushPromises();expect(state.error.value).toBe('流量检索失败');expect(state.range.value).toBe(range);request.mockRejectedValueOnce(new Error('索引未完成'));state.refresh();await flushPromises();expect(state.error.value).toBe('索引未完成');expect(state.pending.value).toBe(false)
  ;(session.current as ShallowRef<Principal|null>).value=null;state.refresh();await flushPromises();expect(state.error.value).toContain('检索范围不一致')
 })
})
