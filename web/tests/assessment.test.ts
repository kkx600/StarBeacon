import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {message,Select,Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Alert,Principal} from '../packages/shared/src/types'
import AlertAssessment from '../platform/src/features/alerts/AlertAssessment.vue'
import AlertDetail from '../platform/src/features/alerts/AlertDetail.vue'
import {initialAssessment,assessmentInputError,validAssessment,validAssessmentPage,type AlertAssessment as Record,type AssessmentChange} from '../platform/src/features/alerts/assessment'
import {useAssessment} from '../platform/src/features/alerts/useAssessment'
import {session} from '../platform/src/session'
import {principal,click,button,deferred,closedMessage} from './fixtures'

const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const global={plugins:[registerAnt]},event='event_assessment',digest='a'.repeat(64),props={eventId:event,digest}
const blank:Record={event_id:event,raw_sha256:digest,revision:0,spec:initialAssessment(),owner_id:'',owner_name:'',analyst_id:'',analyst:'',basis:'unreviewed',updated_at:null,expires_at:null}
function saved(change:AssessmentChange):Record{return{...blank,revision:change.expected_revision+1,spec:structuredClone(change.spec),basis:'human',owner_id:change.claim?principal.id:'',owner_name:change.claim?principal.username:'',analyst_id:principal.id,analyst:principal.username,updated_at:'2026-10-03T01:00:00Z',expires_at:'2027-04-01T01:00:00Z'}}
const change:AssessmentChange={expected_revision:0,spec:{status:'closed',verdict:'false_positive',outcome:'unknown',note:'已核对业务流量与检测条件，保存人工结论。',evidence:['case:owned']},claim:true}
const result=saved(change)
beforeEach(()=>{
 (session.current as ShallowRef<Principal|null>).value=principal
 request.mockReset();request.mockImplementation((path:string,options?:{method?:string;body?:AssessmentChange})=>Promise.resolve(options?.method==='POST'?saved(options.body!):path.includes('/history')?{items:[result],next_cursor:''}:blank))
 vi.spyOn(message,'success').mockImplementation(closedMessage)
})
async function notes(){const input=document.body.querySelector<HTMLTextAreaElement>('textarea[aria-label="研判说明"]');expect(input).not.toBeNull();input!.value=change.spec.note;input!.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('告警研判数据契约',()=>{
 it('未研判不能冒充人工结论，成功或阻止的判断必须有证据',()=>{
  expect(validAssessment(blank)).toBe(true);expect(validAssessment(result)).toBe(true)
  for(const v of [null,{}, {...blank,revision:-1},{...blank,basis:'human'},{...blank,spec:{...blank.spec,note:'伪造的结论'}},{...result,raw_sha256:'invalid'},{...result,event_id:'bad/id'},{...result,revision:Number.MAX_SAFE_INTEGER+1},{...result,spec:{...result.spec,verdict:'toString'}},{...result,analyst_id:''},{...result,owner_id:'',owner_name:'unmatched'},{...result,updated_at:null},{...result,spec:{...result.spec,outcome:'success'}}])expect(validAssessment(v)).toBe(false)
  expect(assessmentInputError({...change.spec,verdict:'confirmed',outcome:'success',evidence:[]})).toContain('证据引用')
  expect(assessmentInputError({...change.spec,status:'closed',verdict:'suspicious'})).toContain('明确研判结论')
  expect(assessmentInputError({...change.spec,outcome:'attempt'})).toContain('确认威胁')
  for(const evidence of [[''],['ref','ref'],['r'.repeat(257)],Array.from({length:9},(_,i)=>'ref'+i)])expect(assessmentInputError({...change.spec,evidence})).not.toBe('')
  for(const note of ['', ' leading ', '正文\u0000', '证'.repeat(2049)])expect(assessmentInputError({...change.spec,note})).not.toBe('')
  expect(assessmentInputError({...change.spec,note:'依据\n来源\t检查'})).toBe('')
  expect(assessmentInputError({...change.spec,status:'unknown' as never})).not.toBe('')
  expect(validAssessmentPage({items:[{...result,revision:2},result],next_cursor:''})).toBe(true)
  for(const page of [{items:[result,result],next_cursor:''},{items:[blank],next_cursor:''},{items:[result],next_cursor:'1'},{items:[],next_cursor:'bad'},null])expect(validAssessmentPage(page)).toBe(false)
 })
})

describe('告警研判交互',()=>{
 it('人工误报、关闭、认领和历史查看保留一张业务表格',async()=>{
  const wrapper=mount(AlertAssessment,{props,global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('尚未保存研判');expect(wrapper.findAll('.ant-table')).toHaveLength(0)
  await wrapper.findAllComponents(Select)[1]!.setValue('false_positive','value');await wrapper.findAllComponents(Select)[0]!.setValue('closed','value');await notes();await wrapper.get('textarea[aria-label="证据引用"]').setValue('case:owned');await wrapper.get('input[type="checkbox"]').setValue(true)
  await click('保存研判');expect(message.success).toHaveBeenCalledWith('告警研判已保存');expect(request.mock.calls.find(c=>c[1]?.method==='POST')?.[1].body).toEqual(change)
  await click('查看研判记录');expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('误报');expect(wrapper.text()).toContain('人工研判记录');await click('刷新记录');await click('返回研判');expect(wrapper.findAll('.ant-table')).toHaveLength(0);expect(request.mock.lastCall?.[1].method).not.toBe('POST')
 })
 it('未知提交冻结原请求，确认前无法更改输入或关闭详情',async()=>{
  const alert:Alert={event_id:event,tenant_id:principal.tenant_id,sensor_id:'probe_owned','@timestamp':'2026-10-03T01:00:00Z',observed_at:'2026-10-03T01:00:00Z',received_at:'2026-10-03T01:00:00Z',raw_sha256:digest,source_offset:"0",sequence:"1",source:{},destination:{},network:{},http:{},rule:{id:'1',name:'验收规则'},suricata:{},severity:'high',event:{kind:'alert',original:''},evidence_status:'unavailable'}
  const wrapper=mount(AlertDetail,{props:{alert},global,attachTo:document.body});await flushPromises();await click('告警研判');await flushPromises();await notes();request.mockRejectedValueOnce(new Error('保存连接中断'));await click('保存研判')
  expect(document.body.textContent).toContain('保存结果尚未确认');expect(wrapper.getComponent(Modal).props('closable')).toBe(false);expect((document.body.querySelector('textarea[aria-label="研判说明"]') as HTMLTextAreaElement).disabled).toBe(true)
  const original=request.mock.calls.filter(c=>c[1]?.method==='POST')[0]!
  request.mockResolvedValueOnce(saved(original[1].body));await click('确认保存结果');const retried=request.mock.calls.filter(c=>c[1]?.method==='POST')[1]!
  expect(retried[1].headers).toEqual(original[1].headers);expect(retried[1].body).toEqual(original[1].body);expect(wrapper.getComponent(Modal).props('closable')).toBe(true);expect(message.success).toHaveBeenCalledWith('研判保存结果已确认')
 })
 it('来源、CAS 和非法表单不允许保存；读取失败保留记录并禁用操作',async()=>{
  const wrapper=mount(AlertAssessment,{props,global,attachTo:document.body});await flushPromises();await click('保存研判');expect(wrapper.text()).toContain('请填写研判说明');expect(request.mock.calls.some(c=>c[1]?.method==='POST')).toBe(false)
  await notes();request.mockRejectedValueOnce(new ApiError(409,'assessment_conflict','其他管理员已更新研判'));await click('保存研判');expect(wrapper.text()).toContain('其他管理员已更新');expect(wrapper.text()).not.toContain('原输入和请求标识已保留')
  request.mockRejectedValueOnce(new Error('研判读取失败'));await click('刷新研判');expect(wrapper.text()).toContain('上次成功读取的研判');expect(button('保存研判').disabled).toBe(true)
  request.mockResolvedValueOnce(result);await click('刷新研判');expect(wrapper.text()).toContain('修订 1');expect(button('保存研判').disabled).toBe(false)
  await wrapper.findAllComponents(Select)[1]!.setValue('confirmed','value');await wrapper.findAllComponents(Select)[2]!.setValue('success','value');await wrapper.get('textarea[aria-label="证据引用"]').setValue('');await click('保存研判');expect(wrapper.text()).toContain('需要提供可复核的证据引用')
 })
 it('历史分页、空状态和失败保留记录可区分',async()=>{
  const wrapper=mount(AlertAssessment,{props,global,attachTo:document.body});await flushPromises()
  const twenty=Array.from({length:20},(_,i)=>({...result,revision:22-i}));request.mockResolvedValueOnce({items:twenty,next_cursor:'3'});await click('查看研判记录');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  request.mockResolvedValueOnce({items:[{...result,revision:2},result],next_cursor:''});await click('加载更早记录');expect(wrapper.findAll('.ant-table-row')).toHaveLength(22)
  request.mockRejectedValueOnce(new Error('记录读取失败'));await click('刷新记录');expect(wrapper.text()).toContain('上次成功读取的记录');expect(wrapper.findAll('.ant-table-row')).toHaveLength(22)
  request.mockResolvedValueOnce({items:[],next_cursor:''});await click('刷新记录');expect(wrapper.text()).toContain('暂无研判记录');expect(wrapper.findAll('.ant-table')).toHaveLength(0)
  request.mockRejectedValueOnce(new Error('历史服务不可用'));await click('刷新记录');expect(wrapper.text()).toContain('历史服务不可用');await click('重试')
 })
})

describe('研判请求边界',()=>{
 function hook(){let state!:ReturnType<typeof useAssessment>;const wrapper=mount(defineComponent({setup(){state=useAssessment(event,digest);return()=>h('div')}}));return{state,wrapper}}
 it('不完整或错配响应不能冒充保存成功，关闭视图后迟到结果不写入',async()=>{
  const {state,wrapper}=hook();request.mockResolvedValueOnce({...blank,event_id:'foreign'});await state.refresh();expect(state.error.value).toContain('未能完整返回')
  await state.refresh();request.mockResolvedValueOnce({...result,spec:{...result.spec,note:'changed'}});await state.save(change);expect(state.unconfirmed.value).toBe(true);await state.save({...change,claim:false});expect(state.actionError.value).toContain('先确认原请求')
  request.mockRejectedValueOnce('offline');await state.confirm();expect(state.actionError.value).toContain('尚未确认')
  const pending=deferred<Record>();request.mockImplementationOnce(()=>pending.promise);const saving=state.confirm();await state.save(change);expect(state.busy.value).toBe(true);const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve(result);await saving;expect(state.current.value?.revision).toBe(0);await state.refresh();await state.loadHistory();await state.save(change)
 })
 it('刷新代次、历史身份和响应异常都保留可解释的失败',async()=>{
  const {state,wrapper}=hook();const stale=deferred<Record>();request.mockImplementationOnce(()=>stale.promise);const first=state.refresh();await state.refresh();stale.resolve(result);await first;expect(state.current.value?.revision).toBe(0)
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('研判记录读取失败')
  request.mockResolvedValueOnce({items:[{...result,event_id:'foreign'}],next_cursor:''});await state.loadHistory();expect(state.historyError.value).toContain('未能完整返回')
  request.mockRejectedValueOnce('offline');await state.loadHistory();expect(state.historyError.value).toBe('研判历史读取失败')
  const pending=deferred<{items:Record[];next_cursor:string}>();request.mockImplementationOnce(()=>pending.promise);const loading=state.loadHistory();wrapper.unmount();pending.resolve({items:[result],next_cursor:''});await loading;expect(state.history.value).toHaveLength(0)
 })
})
