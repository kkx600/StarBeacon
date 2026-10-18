import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {shallowRef} from 'vue'
import {registerAnt} from '../packages/shared/src/ant'
import {qualityCounters,type QualityReport,type QualityCounterKey} from '../packages/shared/src/detectionQuality'
import {localQualityTime,qualityQuery,readQualityPage,type QualityEvent,type QualityPage,type QualityQuery} from '../packages/shared/src/qualityEvents'
import QualityEventsPanel from '../packages/shared/src/components/QualityEventsPanel.vue'
import QualityEventsFilters from '../packages/shared/src/components/QualityEventsFilters.vue'
import QualityEventsWorkspace from '../platform/src/features/sensors/QualityEventsWorkspace.vue'
import DetectionQuality from '../packages/shared/src/components/DetectionQuality.vue'
const {request,current}=vi.hoisted(()=>({request:vi.fn(),current:{value:{tenant_id:'tenant_owned',id:'user_owned',role:'admin',csrf_token:'owned'}}}))
vi.mock('../platform/src/session',async()=>{const {shallowRef}=await import('vue');const reactiveCurrent=shallowRef(current.value);Object.defineProperty(current,'value',{get:()=>reactiveCurrent.value,set:value=>{reactiveCurrent.value=value}});return {session:{api:{request},current}}})
const global={plugins:[registerAnt]}
const query:QualityQuery={start:'2026-10-18T00:00:00Z',end:'2026-10-18T01:00:00Z',page:'1'}
function fixture(q=query):QualityPage{
 const sampled=new Date(Date.parse(q.start)+6000).toISOString(),facet=()=>({state:'no_reported_change' as const,reasons:[]})
 const report:QualityReport={schema_version:1,scope:'sensor_interval',source:'suricata_eve_stats',state:'observed',engine_run_id:'engine_owned',config_sha256:'a'.repeat(64),evaluated_at:sampled,sampled_at:sampled,received_at:sampled,interval_started_at:new Date(Date.parse(q.start)+1000).toISOString(),reset_counters:[],counters:Object.entries(qualityCounters).map(([key,[,layer,kind]])=>({key:key as QualityCounterKey,layer,kind,total:key==='capture.kernel_drops'?'9007199254740993':'0',...(kind==='counter'?{delta:key==='capture.kernel_drops'?'2':'0'}:{})})),capture:{state:'limited',reasons:['capture.kernel_drops']},inspection:facet(),alerting:facet(),policy:facet()}
 return {items:[{schema_version:1,id:'b'.repeat(64),tenant_id:'tenant_owned',sensor_id:'probe_owned',sensor_registration_id:'reg_owned',created_at:sampled.replace('.000Z','.000000001Z'),signal:{kind:'limitation',reasons:['capture.kernel_drops'],fingerprint:'c'.repeat(64)},report}],total:'1',page:Number(q.page),page_size:20}
}
beforeEach(()=>{request.mockReset();current.value={tenant_id:'tenant_owned',id:'user_owned',role:'admin',csrf_token:'owned'};request.mockImplementation((path:string)=>{const p=new URLSearchParams(path.split('?')[1]);return Promise.resolve(fixture(Object.fromEntries(p) as unknown as QualityQuery))})})

describe('质量事件范围与历史回执',()=>{
 it('保存纳秒和原生大数，查询参数拒绝无限时间与非法身份',()=>{
  const got=readQualityPage(fixture(),query,'tenant_owned');expect(got.items[0]!.report.counters[1]!.total).toBe('9007199254740993');expect(got.items[0]!.created_at).toContain('000000001Z');expect(got).not.toBe(fixture())
  const form={start:localQualityTime(new Date(query.start)),end:localQualityTime(new Date(query.end)),sensor:'probe_owned',registration:'reg_owned',kind:'limitation'};expect(qualityQuery(form,2)).toMatchObject({sensor_id:'probe_owned',registration_id:'reg_owned',kind:'limitation',page:'2'})
  for(const change of [{start:'bad'},{end:'2026-12-01T00:00:00'},{end:form.start},{sensor:''},{sensor:'bad/id'},{registration:'bad/id'},{kind:'safe'}])expect(()=>qualityQuery({...form,...change})).toThrow();expect(()=>qualityQuery(form,501)).toThrow()
 })
 it.each([
  ['tenant',(p:QualityPage)=>{p.items[0]!.tenant_id='other'}],['id',(p:QualityPage)=>{p.items[0]!.id='invalid'}],['count',(p:QualityPage)=>{p.total='01'}],['count-limit',(p:QualityPage)=>{p.total='9223372036854775808'}],['page',(p:QualityPage)=>{p.page=2}],['size',(p:QualityPage)=>{p.page_size=30 as 20}],['missing',(p:QualityPage)=>{p.items=[]}],['duplicate',(p:QualityPage)=>{p.items.push(p.items[0]!);p.total='2'}],['time',(p:QualityPage)=>{p.items[0]!.created_at=query.end}],['report',(p:QualityPage)=>{p.items[0]!.report.config_sha256='bad'}],['reason',(p:QualityPage)=>{p.items[0]!.signal.reasons=['tcp.reassembly_gap']}],['type',(p:QualityPage)=>{p.items[0]!.signal.kind='policy'}],['prior',(p:QualityPage)=>{p.items[0]!.signal.prior_event_id='a'.repeat(64)}],['schema',(p:QualityPage)=>{p.items[0]!.schema_version=2 as 1}],['reminder',(p:QualityPage)=>{p.items[0]!.signal.reminder='bad' as unknown as boolean}],
 ] as const)('拒绝不完整的 %s',(_name,change)=>{const page=fixture();change(page);expect(()=>readQualityPage(page,query,'tenant_owned')).toThrow()})
 it('明确的空页可返回，筛选不能串探针或事件类型',()=>{
  expect(readQualityPage({items:[],total:'0',page:2,page_size:20},{...query,page:'2'},'tenant_owned').items).toEqual([])
  for(const q of [{...query,sensor_id:'other'},{...query,registration_id:'other'},{...query,kind:'policy'}])expect(()=>readQualityPage(fixture(),q,'tenant_owned')).toThrow()
  expect(()=>readQualityPage(null,query,'tenant_owned')).toThrow();expect(()=>readQualityPage(fixture(),{...query,start:'bad'},'tenant_owned')).toThrow()
 })
 it('策略与未知区间分别读取，排序及精确总数不能混淆',()=>{
  const p=fixture(),e=p.items[0]!;e.signal.kind='policy';e.signal.reasons=['detect.alerts_suppressed'];e.report.counters[1]!.delta='0';e.report.capture={state:'no_reported_change',reasons:[]};e.report.policy={state:'policy_applied',reasons:['detect.alerts_suppressed']};e.report.counters[22]!.total='1';e.report.counters[22]!.delta='1';expect(readQualityPage(p,query,'tenant_owned').items).toHaveLength(1)
  e.signal.kind='uncertain';e.signal.reasons=['sample_gap'];e.report.state='sample_gap';delete e.report.interval_started_at;e.report.counters.forEach(c=>{delete c.delta});for(const layer of ['capture','inspection','alerting','policy'] as const)e.report[layer]={state:'unknown',reasons:[]};expect(readQualityPage(p,query,'tenant_owned').items).toHaveLength(1);e.signal.reasons=['stale'];expect(()=>readQualityPage(p,query,'tenant_owned')).toThrow()
  const rows=fixture();rows.items.push({...structuredClone(rows.items[0]!),id:'d'.repeat(64)});rows.total='2';expect(readQualityPage(rows,query,'tenant_owned').items).toHaveLength(2);rows.items.reverse();expect(()=>readQualityPage(rows,query,'tenant_owned')).toThrow()
 })
 it('清除和重新可观测不宣称检测完整，拒绝缺少关联事件或持续恢复提醒',()=>{
  for(const kind of ['interval_clear','observation_resumed'] as const){const p=fixture(),e=p.items[0]!;e.signal.kind=kind;e.signal.prior_event_id='a'.repeat(64);e.report.counters[1]!.delta='0';e.report.capture={state:'no_reported_change',reasons:[]};e.signal.reasons=kind==='interval_clear'?['capture.kernel_drops']:['continuous_interval'];expect(readQualityPage(p,query,'tenant_owned').items).toHaveLength(1);e.signal.reminder=true;expect(()=>readQualityPage(p,query,'tenant_owned')).toThrow();delete e.signal.reminder;delete e.signal.prior_event_id;expect(()=>readQualityPage(p,query,'tenant_owned')).toThrow()}
 })
})

describe('质量事件交互',()=>{
 it('历史详情不随当前时钟失效，任一视图只有一张业务表',async()=>{
  vi.useFakeTimers();const p=fixture(),wrapper=mount(QualityEventsPanel,{props:{result:p,pending:false,error:'',attempted:true},global,attachTo:document.body});expect(document.querySelectorAll('.ant-table-wrapper')).toHaveLength(1)
  await wrapper.findAll('button').find(b=>b.text()==='详情')!.trigger('click');await flushPromises();expect(wrapper.find('section.quality-history').exists()).toBe(false);expect(document.querySelectorAll('.ant-table-wrapper')).toHaveLength(1);expect(document.body.textContent).toContain('历史区间快照');expect(document.body.textContent).toContain('9,007,199,254,740,993');expect(document.body.textContent).toContain('存在覆盖限制');expect(document.body.textContent).not.toContain('观测已过期')
  await vi.advanceTimersByTimeAsync(60000);expect(document.body.textContent).toContain('存在覆盖限制');document.querySelector<HTMLButtonElement>('.quality-close button')!.click();await flushPromises();expect(wrapper.find('section.quality-history').exists()).toBe(true);wrapper.unmount();vi.useRealTimers()
 })
 it('缺测、失败、读取中与分页均有可用入口',async()=>{
  const wrapper=mount(QualityEventsPanel,{props:{result:null,pending:false,error:'',attempted:false},global});expect(wrapper.text()).toContain('筛选条件后查询');await wrapper.setProps({attempted:true});expect(wrapper.text()).toContain('空结果不证明检测完整');await wrapper.setProps({error:'索引不可用'});await wrapper.get('button').trigger('click');expect(wrapper.emitted('retry')).toHaveLength(1);await wrapper.setProps({error:'',pending:true});expect(wrapper.text()).toContain('正在读取');await wrapper.setProps({pending:false,result:{...fixture(),total:'21'}});await wrapper.findAll('button').find(b=>b.text()==='下一页')!.trigger('click');expect(wrapper.emitted('page')![0]).toEqual([2]);wrapper.unmount()
 })
 it('查询、变化后取消、重置与超时不沿用旧结果',async()=>{
  const wrapper=mount(QualityEventsWorkspace,{global});await flushPromises();expect(wrapper.findComponent(QualityEventsPanel).props('result')?.items).toHaveLength(1)
  let resolve!:(v:unknown)=>void;request.mockImplementation(()=>new Promise(done=>{resolve=done}));wrapper.findComponent(QualityEventsFilters).vm.$emit('query');await flushPromises();const options=request.mock.lastCall![1];await wrapper.get('#quality-sensor').setValue('probe_changed');expect(options.signal.aborted).toBe(true);resolve(fixture());await flushPromises();expect(wrapper.findComponent(QualityEventsPanel).props('result')).toBeNull()
  wrapper.findComponent(QualityEventsFilters).vm.$emit('query');await flushPromises();wrapper.findComponent(QualityEventsFilters).vm.$emit('cancel');await flushPromises();expect(wrapper.text()).toContain('查询已取消')
  request.mockRejectedValueOnce(new Error('索引暂不可用'));wrapper.findComponent(QualityEventsPanel).vm.$emit('retry');await flushPromises();expect(wrapper.text()).toContain('索引暂不可用')
  await wrapper.get('#quality-start').setValue('bad');wrapper.findComponent(QualityEventsFilters).vm.$emit('query');await flushPromises();expect(wrapper.text()).toContain('请核对探针');wrapper.unmount()
 })
 it('冻结历史组件不注册实时时钟，筛选和重置事件按用户操作发出',async()=>{
  vi.useFakeTimers();const intervalSpy=vi.spyOn(globalThis,'setInterval');const event=fixture().items[0]!,wrapper=mount(DetectionQuality,{props:{capture:{status:'running',config_sha256:event.report.config_sha256,quality:event.report},historical:true},global});expect(intervalSpy.mock.calls.some(([,duration])=>duration===1000)).toBe(false);wrapper.unmount();intervalSpy.mockRestore();vi.useRealTimers()
  const model=shallowRef({start:'',end:'',sensor:'',registration:'',kind:''}),filters=mount(QualityEventsFilters,{props:{modelValue:model.value,pending:false},global});await filters.get('form').trigger('submit');await flushPromises();expect(filters.emitted('query')).toHaveLength(1);await filters.findAll('button').find(b=>b.text().replace(/\s/g,'')==='重置')!.trigger('click');expect(filters.emitted('reset')).toHaveLength(1);await filters.setProps({pending:true});await filters.findAll('button').find(b=>b.text()==='取消查询')!.trigger('click');expect(filters.emitted('cancel')).toHaveLength(1);filters.unmount()
 })
 it('身份变化立即取消旧租户请求，迟到回执不能写入新会话',async()=>{
  let resolve!:(value:unknown)=>void;request.mockImplementationOnce(()=>new Promise(done=>{resolve=done}));const wrapper=mount(QualityEventsWorkspace,{global});await flushPromises();const oldSignal=request.mock.lastCall![1].signal as AbortSignal
  request.mockImplementation((path:string)=>{const q=Object.fromEntries(new URLSearchParams(path.split('?')[1])) as unknown as QualityQuery,p=fixture(q);p.items[0]!.tenant_id='tenant_other';return Promise.resolve(p)});current.value={...current.value,tenant_id:'tenant_other'};await flushPromises();expect(oldSignal.aborted).toBe(true);resolve(fixture());await flushPromises();expect(wrapper.findComponent(QualityEventsPanel).props('result')?.items[0]?.tenant_id).toBe('tenant_other');wrapper.unmount()
 })
 it('请求超时展示错误而不回显旧结果，重置重新冻结时间窗口',async()=>{
  vi.useFakeTimers();request.mockImplementation((_path:string,{signal}:{signal:AbortSignal})=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('已取消','AbortError')))))
  const wrapper=mount(QualityEventsWorkspace,{global});await vi.advanceTimersByTimeAsync(12001);expect(wrapper.text()).toContain('读取超时');expect(wrapper.findComponent(QualityEventsPanel).props('result')).toBeNull();request.mockImplementation((path:string)=>Promise.resolve(fixture(Object.fromEntries(new URLSearchParams(path.split('?')[1])) as unknown as QualityQuery)));wrapper.findComponent(QualityEventsFilters).vm.$emit('reset');await flushPromises();expect(wrapper.findComponent(QualityEventsPanel).props('result')?.items).toHaveLength(1);wrapper.unmount();vi.useRealTimers()
 })
})
