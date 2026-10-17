import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {Select,InputNumber,Switch,Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal} from '../packages/shared/src/types'
import {ApiError} from '../packages/shared/src/api'
import {session} from '../platform/src/session'
import {useRuleSync} from '../platform/src/features/rules/useRuleSync'
import {syncInputError,syncPlanValid,type RuleSyncChange,type RuleSyncPlan} from '../platform/src/features/rules/sync'
import RuleSyncForm from '../platform/src/features/rules/RuleSyncForm.vue'
import RuleSyncWorkspace from '../platform/src/features/rules/RuleSyncWorkspace.vue'
import {principal,rulePackage,sensor,deferred,click} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
const change:RuleSyncChange={id:'sync_office',expected_revision:0,spec:{name:'办公网规则同步',enabled:true,sensor_id:sensor.id,registration_id:sensor.registration_id,package_id:rulePackage.id,package_revision:rulePackage.revision,positive_sample_id:'sample_positive',negative_sample_id:'sample_negative',interval_seconds:60}}
const plan:RuleSyncPlan={id:change.id,revision:1,spec:{...change.spec},created_by:principal.id,updated_at:new Date().toISOString(),next_at:new Date().toISOString(),processed_revision:0}
const run={id:'sync_run_1',plan_revision:1,spec:{...change.spec},created_by:principal.id,state:'validating',code:'',stage:0,tasks:['task_validate','','',''] as [string,string,string,string],expected_sha256:'a'.repeat(64),created_at:new Date().toISOString(),expires_at:new Date(Date.now()+86400000).toISOString()}
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/sensors')?{items:[sensor],next_cursor:''}:path==='/rule-packages'?{items:[rulePackage]}:{items:[plan],next_cursor:''}))})
function host(){let state!:ReturnType<typeof useRuleSync>;const wrapper=mount(defineComponent({setup(){state=useRuleSync();return()=>h('div')}}));return {state,wrapper}}
async function view(){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/rules',component:RuleSyncWorkspace},{path:'/sensors',component:{render:()=>h('div')}}]});await router.push('/rules');await router.isReady();const wrapper=mount(RuleSyncWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return wrapper}
function formProps(){return{plan:null,sensors:[sensor],packages:[rulePackage],busy:false,locked:false,error:'',choicesError:'',choicesPending:false}}

describe('规则同步输入与返回边界',()=>{
 it('验证完整输入、阶段、任务和目录来源',()=>{
  expect(syncInputError(change)).toBe('');expect(syncPlanValid(plan)).toBe(true);expect(syncPlanValid({...plan,run})).toBe(true)
  for(const c of [{...change,id:'bad/id'},{...change,expected_revision:-1},...[
   {name:''},{name:' 前空格'},{name:'a\nb'},{name:'名'.repeat(129)},{sensor_id:''},{registration_id:''},{package_id:''},{package_revision:0},{positive_sample_id:''},{negative_sample_id:change.spec.positive_sample_id},{interval_seconds:29},{interval_seconds:3601},{interval_seconds:30.5},
  ].map(s=>({...change,spec:{...change.spec,...s}}))])expect(syncInputError(c)).not.toBe('')
  for(const value of [null,{}, {...plan,revision:0},{...plan,created_by:''},{...plan,processed_revision:-1},{...plan,updated_at:'bad'},...[
   {id:'bad/id'},{plan_revision:0},{plan_revision:2},{state:'unknown'},{stage:5},{tasks:['bad/id','','','']},{tasks:[]},{code:null},{expected_sha256:null},{created_at:'bad'},
  ].map(r=>({...plan,run:{...run,...r}}))])expect(syncPlanValid(value as RuleSyncPlan)).toBe(false)
 })
})
describe('规则同步目录与提交一致性',()=>{
 it('分页只前进到有效游标，目录缺失、重复或倒退均拒绝',async()=>{
  request.mockResolvedValue({items:[plan],next_cursor:plan.id});const {state}=host();await flushPromises();expect(state.page.value.items).toHaveLength(1)
  request.mockResolvedValueOnce({items:[],next_cursor:''});state.next();await flushPromises();expect(request.mock.lastCall?.[0]).toContain('cursor=sync_office');state.previous();await flushPromises();state.previous();expect(state.cursors.value).toHaveLength(1)
  for(const p of [{},{items:[plan,plan],next_cursor:''},{items:[plan],next_cursor:'foreign'},{items:[{}],next_cursor:''},{items:[],next_cursor:5}]){request.mockResolvedValueOnce(p);await state.refresh();expect(state.error.value).toContain('完整')}
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('规则同步计划读取失败')
  request.mockRejectedValueOnce(new Error('读取超时'));await state.refresh();expect(state.error.value).toBe('读取超时')
 })
 it('旧列表与选项响应不会覆盖当前请求或离开后的页面',async()=>{
  const {state,wrapper}=host();await flushPromises();const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const first=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal
  request.mockResolvedValueOnce({items:[],next_cursor:''});await state.refresh();old.resolve({items:[plan],next_cursor:''});await first;expect(signal.aborted).toBe(true);expect(state.page.value.items).toEqual([])
  const waiting=deferred<unknown>();request.mockReturnValue(waiting.promise);const open=state.open(null);const selectedSignal=request.mock.lastCall?.[1].signal as AbortSignal;state.close();waiting.resolve({items:[],next_cursor:''});await open;expect(selectedSignal.aborted).toBe(true);expect(state.editing.value).toBeUndefined()
  wrapper.unmount();const n=request.mock.calls.length;await state.refresh();await state.open(null);await state.save(change);expect(request).toHaveBeenCalledTimes(n)
 })
 it('选项错误可恢复，迟到错误不显示；权限变化清理计划与未确认请求',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce('offline');await state.open(null);expect(state.choicesError.value).toBe('可用探针与规则包读取失败')
  request.mockRejectedValueOnce(new Error('选项超时'));await state.open(plan);expect(state.choicesError.value).toBe('选项超时')
  const fail=deferred<unknown>();request.mockReturnValue(fail.promise);const opening=state.open(null);state.close();fail.reject(new Error('迟到'));await opening;expect(state.choicesError.value).toBe('')
  user.value={...principal,role:'viewer'};await flushPromises();const n=request.mock.calls.length;await state.open(null);await state.save(change);await state.refresh();expect(request).toHaveBeenCalledTimes(n);expect(state.page.value.items).toEqual([])
 })
 it('保存准确绑定授权修订；未知结果使用相同输入核对，不产生替代计划',async()=>{
  const {state}=host();await flushPromises();await state.open(null)
  request.mockRejectedValueOnce(new Error('连接中断'));await state.save(change);expect(state.unconfirmed.value).toEqual(change)
  await state.save({...change,spec:{...change.spec,name:'其他名称'}});expect(state.formError.value).toContain('原提交')
  await state.open(plan);expect(state.editing.value).toBeNull()
  request.mockResolvedValueOnce({...plan,revision:2});await state.save(change);expect(state.formError.value).toContain('原提交')
  request.mockResolvedValueOnce(plan);state.confirm();await flushPromises();expect(state.unconfirmed.value).toBeUndefined();expect(state.editing.value).toBeUndefined()
  const posts=request.mock.calls.filter(c=>c[1]?.method==='POST');expect(posts).toHaveLength(3);expect(posts.every(c=>JSON.stringify(c[1].body)===JSON.stringify(change))).toBe(true)
  state.confirm();await state.save({...change,id:''});expect(state.formError.value).toContain('标识')
 })
 it('明确拒绝允许修正，提交中禁止重复和关闭，卸载不误报迟到结果',async()=>{
  const {state,wrapper}=host();await flushPromises();await state.open(plan);request.mockRejectedValueOnce(new ApiError(409,'conflict','修订冲突'));await state.save(change);expect(state.unconfirmed.value).toBeUndefined()
  request.mockRejectedValueOnce(new ApiError(503,'rule_sync_unavailable','执行服务未配置'));await state.save(change);expect(state.unconfirmed.value).toBeUndefined();expect(state.formError.value).toBe('执行服务未配置')
  request.mockRejectedValueOnce('offline');await state.save(change);expect(state.formError.value).toBe('规则同步计划保存失败')
  const wait=deferred<unknown>();request.mockReturnValueOnce(wait.promise);const action=state.save(change);await state.save(change);state.close();expect(state.editing.value?.id).toBe(plan.id)
  const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();wait.resolve(plan);await action;expect(signal.aborted).toBe(true)
 })
})
describe('规则同步页面操作',()=>{
 it('选择框的 Esc 只关闭选项并保留草稿，仍可显式关闭表单',async()=>{
  const wrapper=mount(RuleSyncForm,{props:formProps(),global:{plugins:[registerAnt]},attachTo:document.body});const input=document.querySelector<HTMLInputElement>('input[aria-label="计划名称"]')!;input.value='保留规则同步草稿';input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()
  for(const select of wrapper.findAllComponents(Select)){
   await select.find('.ant-select-selector').trigger('mousedown');await flushPromises();expect(select.find('input').attributes('aria-expanded')).toBe('true')
   const escape=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(escape,'which',{value:27});select.find('input').element.dispatchEvent(escape);await flushPromises();expect(wrapper.emitted('close')).toBeUndefined();expect(select.find('input').attributes('aria-expanded')).toBe('false');expect(input.value).toBe('保留规则同步草稿')
  }
  await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('操作位于独立页脚，修正输入清除本地校验，选项不可用时禁止表单提交',async()=>{
  const wrapper=mount(RuleSyncForm,{props:formProps(),global:{plugins:[registerAnt]},attachTo:document.body});await click('保存计划');expect(document.body.textContent).toContain('请填写 1–128 字的计划名称')
  expect(document.querySelector('.ant-modal-footer')?.textContent).toContain('保存计划');expect(document.querySelector('.ant-modal-body')?.textContent).not.toContain('保存计划')
  const input=document.querySelector<HTMLInputElement>('input[aria-label="计划名称"]')!;input.value='办公网规则同步';input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises();expect(document.body.textContent).not.toContain('请填写 1–128 字的计划名称')
  await wrapper.setProps({choicesError:'探针目录暂不可用'});document.querySelector('form')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await flushPromises();expect(wrapper.emitted('save')).toBeUndefined();expect(document.body.textContent).toContain('探针目录暂不可用')
 })
 it('重注册后必须显式采用当前设备代次，不能用旧授权代次继续提交',async()=>{
  const wrapper=mount(RuleSyncForm,{props:{...formProps(),plan,sensors:[{...sensor,registration_id:'registration_current'}]},global:{plugins:[registerAnt]},attachTo:document.body});expect(document.body.textContent).toContain('注册代次已变化');await click('使用当前代次');await click('保存计划');expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({expected_revision:1,spec:{registration_id:'registration_current'}})
 })
 it('表单选择绑定注册代次和具体修订；校验、保存与关闭均有明确结果',async()=>{
  const wrapper=mount(RuleSyncForm,{props:formProps(),global:{plugins:[registerAnt]},attachTo:document.body});await click('保存计划');expect(document.body.textContent).toContain('名称')
  const input=document.querySelector<HTMLInputElement>('input[aria-label="计划名称"]')!;input.value=change.spec.name;input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()
  const selects=wrapper.findAllComponents(Select);await selects[0]!.setValue(sensor.id,'value');selects[0]!.vm.$emit('change',sensor.id);await selects[1]!.setValue(rulePackage.id,'value');selects[1]!.vm.$emit('change',rulePackage.id)
  for(const [label,value] of [['正样本标识','sample_positive'],['反样本标识','sample_negative']]){const field=document.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;field.value=value!;field.dispatchEvent(new Event('input',{bubbles:true}))};await wrapper.getComponent(Switch).setValue(true,'checked');await click('保存计划')
  expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({expected_revision:0,spec:change.spec});await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
  await selects[0]!.setValue('missing','value');selects[0]!.vm.$emit('change','missing');await selects[1]!.setValue('missing','value');selects[1]!.vm.$emit('change','missing');await click('保存计划');expect(document.body.textContent).toContain('注册')
 })
 it('在途阶段只允许停用，未确认输入锁定并保留核对入口',async()=>{
  const wrapper=mount(RuleSyncForm,{props:{...formProps(),plan:{...plan,run},locked:true,error:'受理结果尚未确认'},global:{plugins:[registerAnt]},attachTo:document.body});expect(wrapper.getComponent(Select).props('disabled')).toBe(true);expect(wrapper.findAllComponents(InputNumber).every(c=>c.props('disabled'))).toBe(true)
  await click('核对原提交');expect(wrapper.emitted('confirm')).toHaveLength(1);wrapper.getComponent(Modal).vm.$emit('cancel');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('页面使用单表、详情与任务链接；空状态和编辑使用同一工作区',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/rule-sync-plans')?{items:[{...plan,run}],next_cursor:''}:path.startsWith('/sensors')?{items:[sensor],next_cursor:''}:{items:[rulePackage]}))
  const wrapper=await view();expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('查看');expect(document.body.textContent).toContain('授权修订 1');expect(document.body.querySelector('a[href="/sensors?view=tasks&task=task_validate"]')).not.toBeNull()
  wrapper.getComponent(Modal).vm.$emit('cancel');await flushPromises();await click('配置');expect(document.body.textContent).toContain('规则同步计划');wrapper.getComponent(RuleSyncForm).vm.$emit('close');await flushPromises()
  await click('创建同步计划');expect(document.body.textContent).toContain('创建规则同步计划');wrapper.getComponent(RuleSyncForm).vm.$emit('close');await flushPromises()
  request.mockResolvedValueOnce({items:[],next_cursor:''});await click('刷新');expect(wrapper.text()).toContain('暂无规则同步计划')
 })
})
