import {webcrypto,randomUUID} from 'node:crypto'
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {Form,Select,InputNumber} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import CorrelationRuleForm from '../packages/shared/src/components/CorrelationRuleForm.vue'
import CorrelationRuleDetail from '../packages/shared/src/components/CorrelationRuleDetail.vue'
import CorrelationRuleTable from '../packages/shared/src/components/CorrelationRuleTable.vue'
import CorrelationScopeForm from '../packages/shared/src/components/CorrelationScopeForm.vue'
import CorrelationResultTable from '../packages/shared/src/components/CorrelationResultTable.vue'
import {correlationChangeError,definitionError,definitionShape,emptyCorrelationDefinition,emptyCorrelationQuery,readCorrelationRule,readCorrelationPage,readCorrelationReceipt,readCorrelationResult,correlationRequestError,type CorrelationChange,type CorrelationDefinition,type CorrelationResult} from '../packages/shared/src/correlation'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {correlationRule as rule,correlationQuery as query,correlationResult as result,correlationEmpty as empty} from './correlation-fixture'
import {click} from './fixtures'
const wrappers:VueWrapper[]=[]
const body=()=>new DOMWrapper(document.body)
function ui(component:Parameters<typeof mount>[0],props:Record<string,unknown>={}){const w=mount(component,{props,global:{plugins:[registerAnt]},attachTo:document.body}) as VueWrapper<any>;wrappers.push(w);return w}
const input=():CorrelationChange=>({id:rule.id,expected_revision:0,name:rule.name,description:rule.description,active:true,definition:definitionShape(rule.definition)})
const clone=<T>(v:T):T=>JSON.parse(JSON.stringify(v)) as T
async function cursor(after:string,q=emptyCorrelationQuery()){const raw=JSON.stringify({after,scope:await goJSONDigest({tenant:rule.tenant_id,query:{...q,cursor:''}})});return btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
async function finish(w:VueWrapper){w.getComponent(Form).vm.$emit('finish',{});await flushPromises()}
beforeEach(()=>{vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID});vi.spyOn(Date,'now').mockReturnValue(Date.parse('2026-10-22T00:00:00Z'))})
afterEach(()=>{vi.useRealTimers();wrappers.splice(0).forEach(w=>w.unmount());document.body.innerHTML='';vi.unstubAllGlobals()})
describe('关联规则与证据数据契约',()=>{
 it('支持计数与不同值条件，拒绝未知语义、无效边界及不可写字段',()=>{
  expect(emptyCorrelationQuery()).toEqual({cursor:'',keyword:'',active:'',limit:20});expect(definitionError(emptyCorrelationDefinition())).toBe('');expect(correlationChangeError(input())).toBe('')
  for(const value of [null,{}, {...rule.definition,extra:true},{...rule.definition,dataset:'logs'},{...rule.definition,filter:'x\ny'},{...rule.definition,filter:'汉'.repeat(1400)},{...rule.definition,group_by:'asset.id'},{...rule.definition,metric:'sequence'},{...rule.definition,window_seconds:14},{...rule.definition,window_seconds:3601},{...rule.definition,threshold:1},{...rule.definition,threshold:5001},{...rule.definition,distinct_field:'source.port'},{...rule.definition,metric:'distinct',distinct_field:'source.ip'},{...rule.definition,metric:'distinct',distinct_field:'http.path'}])expect(definitionError(value)).not.toBe('')
  expect(definitionError({...rule.definition,metric:'distinct',distinct_field:'destination.ip'})).toBe('')
  for(const patch of [{id:'/'},{expected_revision:-1},{expected_revision:1000000},{name:' '},{name:'a'.repeat(129)},{description:'a\nb'},{active:null},{definition:{...rule.definition,threshold:0}}])expect(correlationChangeError({...input(),...patch} as CorrelationChange)).not.toBe('')
 })
 it('核对租户、操作者、不可变定义摘要与原提交输入',async()=>{
  expect(await readCorrelationRule(rule,rule.tenant_id)).toEqual(rule);expect(await readCorrelationReceipt(rule,rule.tenant_id,input(),rule.created_by)).toEqual(rule)
  for(const value of [null,{}, {...rule,tenant_id:'other'},{...rule,id:'/'},{...rule,created_by:'/'},{...rule,revision:0},{...rule,name:' x'},{...rule,description:'x\ny'},{...rule,active:1},{...rule,definition_sha256:'0'.repeat(64)},{...rule,created_at:'invalid'},{...rule,expires_at:rule.created_at}])await expect(readCorrelationRule(value,rule.tenant_id)).rejects.toThrow('不一致')
  for(const patch of [{id:'other'},{revision:2},{name:'其他'},{description:'其他'},{active:false},{created_by:'other'}])await expect(readCorrelationReceipt({...rule,...patch},rule.tenant_id,input(),rule.created_by)).rejects.toThrow('不一致')
  await expect(readCorrelationReceipt(rule,rule.tenant_id,{...input(),definition:{...rule.definition,threshold:3}})).rejects.toThrow('不一致')
 })
 it('分页游标同时绑定租户、筛选、容量及最后一个标识',async()=>{
  const q={...emptyCorrelationQuery(),limit:1},next=await cursor(rule.id,q),page={items:[rule],next_cursor:next}
  expect(await readCorrelationPage(page,q,rule.tenant_id)).toEqual(page)
  expect(await readCorrelationPage({items:[],next_cursor:''},{...q,cursor:next},rule.tenant_id)).toEqual({items:[],next_cursor:''})
  for(const [value,request] of [[null,q],[{},q],[{items:[rule,rule],next_cursor:''},q],[{items:[rule],next_cursor:12},q],[{items:[rule],next_cursor:''},{...q,cursor:next}],[{items:[rule],next_cursor:''},{...q,active:'false'}],[page,{...q,limit:2}],[page,{...q,keyword:'other'}],[{...page,next_cursor:await cursor('other',q)},q],[{items:[],next_cursor:next},q],[page,{...q,cursor:'%'}],[page,{...q,cursor:'a'}],[page,{...q,cursor:btoa('{}').replaceAll('=','')}]] as const)await expect(readCorrelationPage(value,request,rule.tenant_id)).rejects.toThrow('不一致')
  await expect(readCorrelationPage(page,q,'other')).rejects.toThrow('不一致')
 })
 it('拒绝未来、非整秒、超一小时与倒置查询，允许较早历史的一小时窗口',()=>{
  expect(correlationRequestError(query)).toBe('');expect(correlationRequestError({...query,start:'2020-01-01T00:00:00Z',end:'2020-01-01T01:00:00Z'})).toBe('')
  for(const patch of [{expected_revision:0},{start:'bad'},{end:'bad'},{start:'1999-01-01T00:00:00Z'},{end:query.start},{start:query.end},{end:'2099-01-01T00:00:00Z'},{start:'2026-10-21T10:00:00Z'},{start:'2026-10-21T11:58:00.000000001Z'}])expect(correlationRequestError({...query,...patch})).not.toBe('')
 })
 it('独立核对窗口身份、计量、证据身份及来源未知，空快照不等于安全',async()=>{
  expect(await readCorrelationResult(result,rule,query)).toEqual(result);expect(await readCorrelationResult(empty,rule,query)).toEqual(empty)
  for(const patch of [{schema_version:'other'},{tenant_id:'other'},{rule_id:'other'},{rule_revision:2},{definition_sha256:'0'.repeat(64)},{query:{...query,expected_revision:2}},{query:{...query,start:'2026-10-21T11:59:00Z'}},{observed_at:'bad'},{observed_at:query.start},{snapshot_sha256:'x'},{unique_events:5001},{duplicate_events:5000},{missing_group:5},{threshold_windows:0},{partial_windows:1},{source_coverage:'complete'},{execution_authorized:true},{windows:null},{windows:[...result.windows].reverse()}])await expect(readCorrelationResult({...result,...patch},rule,query)).rejects.toThrow('不一致')
  await expect(readCorrelationResult(result,rule,{...query,expected_revision:2})).rejects.toThrow('不一致')
  const row=result.windows[0]!
  for(const patch of [{detection_id:'a'.repeat(64)},{sensor_id:'/'},{sensor_registration_id:'other'},{group_value:''},{start:'bad'},{end:row.start},{count:0},{metric_value:1},{missing_metric:1},{evidence_sha256:'x'},{evidence:null},{evidence:[]},{evidence_truncated:true},{status:'confirmed'},{start:row.start.replace(':00Z',':01Z')},{evidence:[...row.evidence].reverse()},{evidence:[{...row.evidence[0],event_id:'/'},row.evidence[1]]},{evidence:[{...row.evidence[0],raw_sha256:'x'},row.evidence[1]]},{evidence:[{...row.evidence[0],timestamp:query.end},row.evidence[1]]}])await expect(readCorrelationResult({...result,windows:[{...row,...patch},result.windows[1]]},rule,query)).rejects.toThrow('不一致')
  await expect(readCorrelationResult({...result,windows:[row,row]},rule,query)).rejects.toThrow('不一致')
 })
 it('不同值、部分窗口和抽样截断保持明确的业务边界',async()=>{
  const d={...rule.definition,metric:'distinct',distinct_field:'destination.ip'} as CorrelationDefinition,r={...rule,definition:d,definition_sha256:await goJSONDigest(definitionShape(d))},v=clone(result)
  v.definition_sha256=r.definition_sha256
  for(const row of v.windows)row.detection_id=await goJSONDigest([r.tenant_id,r.id,String(r.revision),r.definition_sha256,row.sensor_id,row.sensor_registration_id,r.definition.group_by,row.group_value,row.start,'threshold'])
  v.windows[0]!.metric_value=1;v.windows[0]!.missing_metric=1;v.windows[0]!.status='threshold_not_observed';v.threshold_windows=1
  expect(await readCorrelationResult(v,r,query)).toEqual(v)
  await expect(readCorrelationResult({...v,windows:[{...v.windows[0],metric_value:2},v.windows[1]]},r,query)).rejects.toThrow('不一致')
  const partial=clone(result),p={...query,start:'2026-10-21T11:58:01Z'};partial.query=p;partial.windows[0]!.status='partial_window';partial.partial_windows=1;partial.threshold_windows=1
  expect(await readCorrelationResult(partial,rule,p)).toEqual(partial)
  const truncated=clone(result),w=truncated.windows[0]!;w.count=9;w.metric_value=9;w.evidence_truncated=true;w.evidence=Array.from({length:8},(_,n)=>({...w.evidence[0]!,event_id:'a_evidence_'+n}));truncated.unique_events=11
  expect(await readCorrelationResult(truncated,rule,query)).toEqual(truncated)
  await expect(readCorrelationResult({...truncated,windows:[{...w,evidence_truncated:false},truncated.windows[1]]},rule,query)).rejects.toThrow('不一致')
 })
})
describe('关联规则与窗口回测',()=>{
 it('创建表单填写名称后提交受限规则，不克隆响应式代理',async()=>{
  const wrapper=mount(CorrelationRuleForm,{props:{record:null,busy:false,unconfirmed:false,error:''},global:{plugins:[registerAnt]},attachTo:document.body});wrappers.push(wrapper)
  await flushPromises()
  await new DOMWrapper(document.querySelector('#correlation-name')!).setValue('同源多目标活动')
  await click('保存规则');await flushPromises()
  expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({expected_revision:0,name:'同源多目标活动',active:true,definition:{schema_version:'correlation-rule.v1',dataset:'alerts',group_by:'source.ip',metric:'count',window_seconds:300,threshold:20}})
 })
 it('空名称反馈可聚焦，不同值字段随分组变化；未知提交锁定字段与关闭交互',async()=>{
  const w=ui(CorrelationRuleForm,{record:null,busy:false,unconfirmed:false,error:''});await click('保存规则');expect(body().text()).toContain('请填写规则名称');expect(document.activeElement?.getAttribute('aria-label')).toBe('关联规则校验信息')
  await body().get('#correlation-name').setValue('活动模式')
  w.findAllComponents(Select).find(s=>s.props('value')==='count')!.vm.$emit('update:value','distinct');await flushPromises()
  expect(body().text()).toContain('不同值字段');w.findAllComponents(Select).find(s=>s.props('value')==='source.ip')!.vm.$emit('update:value','destination.ip');await flushPromises();await click('保存规则');expect((w.emitted('save')?.[0]?.[0] as CorrelationChange).definition).toMatchObject({metric:'distinct',group_by:'destination.ip',distinct_field:'source.ip'})
  await w.setProps({unconfirmed:true,error:'回执未确认'});await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);await finish(w);expect(w.emitted('save')).toHaveLength(1);await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('编辑保留固定修订及定义，计数切换移除不同值字段',async()=>{
  const w=ui(CorrelationRuleForm,{record:{...rule,definition:{...rule.definition,metric:'distinct',distinct_field:'destination.ip'}},busy:false,unconfirmed:false,error:''})
  w.findAllComponents(Select).find(s=>s.props('value')==='distinct')!.vm.$emit('update:value','count');await flushPromises();await click('保存规则');expect(w.emitted('save')?.[0]?.[0]).toMatchObject({id:rule.id,expected_revision:1,definition:{metric:'count',distinct_field:''}})
 })
 it('输入不完整修订不会逐键查询，明确读取与重试绑定所选修订',async()=>{
  const w=ui(CorrelationRuleDetail,{record:rule,revision:1,maximum:2,error:''});await flushPromises();const n=w.getComponent(InputNumber);n.vm.$emit('update:value','');await flushPromises();expect(body().findAll('button').find(b=>b.text().replace(/\s/g,'')==='读取')?.attributes('disabled')).toBeDefined();n.vm.$emit('update:value',2);await flushPromises();expect(w.emitted('read')).toBeUndefined();await click('读取');expect(w.emitted('read')).toEqual([[2]]);await w.setProps({revision:2,pending:true});n.vm.$emit('update:value',0);await click('关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('目录只有一张表格，启停与权限决定编辑、回测入口',async()=>{
  const w=ui(CorrelationRuleTable,{items:[rule],canEdit:true});expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);await click('查看');await click('编辑');await click('窗口回测');expect(w.emitted('inspect')?.[0]).toEqual([rule]);expect(w.emitted('edit')).toHaveLength(1);expect(w.emitted('backtest')).toHaveLength(1)
  await w.setProps({items:[{...rule,active:false,definition:{...rule.definition,metric:'distinct',distinct_field:'destination.ip'}}],canEdit:false});expect(w.text()).toContain('停用');expect(w.text()).not.toContain('编辑');expect(w.text()).not.toContain('回测')
 })
 it('实际点击提交按钮会通过组件表单校验并提交当前时间范围',async()=>{
  const w=ui(CorrelationScopeForm,{revision:1,windowSeconds:60,initial:query,pending:false});await click('运行回测');await vi.waitFor(()=>expect(w.emitted('run')).toHaveLength(1));expect(w.emitted('run')?.[0]?.[0]).toMatchObject({expected_revision:1,start:'2026-10-21T11:58:00.000Z',end:'2026-10-21T12:00:00.000Z'})
 })
 it('本机时间按 UTC 半开区间提交，无效或未来范围不执行；停止等待仍可点击',async()=>{
  const w=ui(CorrelationScopeForm,{revision:1,windowSeconds:60,initial:query,pending:false});await finish(w);expect(w.emitted('run')?.[0]?.[0]).toMatchObject({expected_revision:1,start:'2026-10-21T11:58:00.000Z',end:'2026-10-21T12:00:00.000Z'})
  await w.get('#correlation-start').setValue('');await finish(w);expect(w.text()).toContain('有效的本机');expect(w.emitted('change')?.length).toBeGreaterThan(0)
  await w.get('#correlation-start').setValue('2099-01-01T00:00:00');await finish(w);expect(w.text()).toContain('单次范围');expect(w.emitted('run')).toHaveLength(1)
  await w.setProps({pending:true});await click('停止等待');expect(w.emitted('cancel')).toHaveLength(1);await finish(w);expect(w.emitted('run')).toHaveLength(1)
 })
 it('证据以详情列表展开，不引入第二张业务表格，复制失败及清空结果可见',async()=>{
  const w=ui(CorrelationResultTable,{result,definition:rule.definition});expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);await click('查看证据');expect(body().text()).toContain('完整证据集合摘要');expect(body().findAll('.ant-table-wrapper')).toHaveLength(1);await click('复制事件标识');expect(body().text()).toContain('无法访问剪贴板');const writeText=vi.fn().mockResolvedValue(undefined);Object.defineProperty(navigator,'clipboard',{value:{writeText},configurable:true});await click('复制事件标识');expect(writeText).toHaveBeenCalledWith(result.windows[0]!.evidence[0]!.event_id);await click('关闭');expect(w.emitted('close')).toHaveLength(1)
  const truncated=clone(result);truncated.windows[0]!.evidence_truncated=true;truncated.windows[0]!.missing_metric=1;await w.setProps({result:truncated,detailID:truncated.windows[0]!.detection_id});expect(body().text()).toContain('当前展示按事件标识排序');expect(body().text()).toContain('计量值未知');await w.setProps({result:empty,detailID:undefined});expect(body().find('.ant-modal-content').exists()).toBe(false);expect(w.text()).toContain('不代表流量安全')
 })
})
