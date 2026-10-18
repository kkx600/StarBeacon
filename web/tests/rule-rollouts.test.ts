import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {Select,Checkbox,InputNumber,Modal} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useRuleRollouts} from '../platform/src/features/rules/useRuleRollouts'
import {batchOf,rolloutInputError,validRollout,sameRolloutSpec,stopReasonError,rolloutTerminal,type RuleRollout,type RolloutCreate} from '../platform/src/features/rules/rollout'
import type {RuleSyncPlan} from '../platform/src/features/rules/sync'
import RuleRolloutForm from '../platform/src/features/rules/RuleRolloutForm.vue'
import RuleRolloutDetail from '../platform/src/features/rules/RuleRolloutDetail.vue'
import RuleRolloutsWorkspace from '../platform/src/features/rules/RuleRolloutsWorkspace.vue'
import {principal,sensor,rulePackage,deferred,click} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
const at='2026-10-18T05:00:00Z'
const plans:RuleSyncPlan[]=[0,1,2].map(i=>({id:'sync_'+i,revision:1,spec:{name:'办公探针 '+i,enabled:false,sensor_id:sensor.id+'_'+i,registration_id:sensor.registration_id+'_'+i,package_id:rulePackage.id,package_revision:rulePackage.revision,positive_sample_id:'sample_positive',negative_sample_id:'sample_negative',interval_seconds:60},created_by:principal.id,updated_at:at,next_at:at,processed_revision:0}))
const input:RolloutCreate={id:'rollout_office',spec:{name:'办公网规则分批发布',plans:plans.map(p=>({plan_id:p.id,revision:p.revision})),canary_count:1,batch_size:2,observation_seconds:30,timeout_seconds:3600}}
const record:RuleRollout={id:input.id,spec:input.spec,created_by:principal.id,state:'pending',code:'',current_batch:0,package_sha256:'a'.repeat(64),created_at:at,deadline:'2026-10-18T06:00:00Z',next_at:at,expires_at:'2027-04-16T05:00:00Z',stop_reason:'',stopped_by:'',targets:plans.map((p,i)=>({ordinal:i,batch:i?1:0,plan_id:p.id,authorized_revision:1,execution_revision:0,spec:p.spec,state:'queued',code:''}))}
const list=()=>({items:[record],next_cursor:''})
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((url:string)=>Promise.resolve(url.startsWith('/rule-sync-plans')?{items:plans,next_cursor:''}:url==='/rule-rollouts/'+record.id?record:list()))})
function host(){let state!:ReturnType<typeof useRuleRollouts>;const wrapper=mount(defineComponent({setup(){state=useRuleRollouts();return()=>h('div')}}));return{state,wrapper}}
const props=()=>({plans,userId:principal.id,busy:false,locked:false,error:'',plansPending:false,plansError:'',hasMore:false})
async function view(){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/rules',component:RuleRolloutsWorkspace},{path:'/sensors',component:{render:()=>h('div')}}]});await router.push('/rules');await router.isReady();const wrapper=mount(RuleRolloutsWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return wrapper}

describe('分批发布冻结范围与回执',()=>{
 it('验证批次、数字、身份、任务与保留期限，拒绝不完整回执',()=>{
  expect(rolloutInputError(input)).toBe('');expect(validRollout(record,true)).toBe(true);expect(validRollout({...record,targets:undefined})).toBe(true);expect(batchOf(input.spec,0)).toBe(0);expect(batchOf(input.spec,2)).toBe(1)
  for(const c of [null,{...input,id:'bad/id'},...[
   {name:''},{name:' 名称'},{name:'名'.repeat(129)},{name:'名称\u0085'},{plans:[]},{plans:[input.spec.plans[0]]},{plans:Array(201).fill(input.spec.plans[0])},{plans:[input.spec.plans[0],input.spec.plans[0]]},{plans:[{plan_id:'bad/id',revision:1},input.spec.plans[1]]},{plans:[{plan_id:'sync_a',revision:0},input.spec.plans[1]]},{canary_count:0},{canary_count:3},{batch_size:0},{batch_size:21},{observation_seconds:29},{observation_seconds:3601},{timeout_seconds:299},{timeout_seconds:86401},{timeout_seconds:300,observation_seconds:300},
  ].map(spec=>({...input,spec:{...input.spec,...spec}}))])expect(rolloutInputError(c as RolloutCreate)).not.toBe('')
  for(const r of [null,{},...[
   {id:'bad/id'},{created_by:''},{state:'__proto__'},{current_batch:2},{package_sha256:'bad'},{created_at:'bad'},{expires_at:at},{stop_reason:null},{stopped_by:'bad/id'},{finished_at:at},{observation_started_at:'bad'},{targets:[]},{targets:record.targets!.map((t,i)=>i?t:{...t,batch:1})},{targets:record.targets!.map((t,i)=>i?t:{...t,authorized_revision:2})},{targets:record.targets!.map((t,i)=>i?t:{...t,execution_revision:3})},{targets:record.targets!.map((t,i)=>i?t:{...t,spec:{...t.spec,enabled:true}})},
  ].map(p=>({...record,...p}))])expect(validRollout(r as RuleRollout,true)).toBe(false)
  expect(validRollout({...record,state:'stopped',finished_at:at},true)).toBe(true);expect(rolloutTerminal('stopping')).toBe(false);expect(rolloutTerminal('blocked')).toBe(true)
  expect(sameRolloutSpec(input.spec,structuredClone(input.spec))).toBe(true);expect(sameRolloutSpec(input.spec,{...input.spec,batch_size:1})).toBe(false)
  for(const reason of ['', ' 原因', '原因\n', '原'.repeat(513)])expect(stopReasonError(reason)).not.toBe('');expect(stopReasonError('现场维护')).toBe('')
 })
 it('独立运行必须属于原计划修订和批准者',()=>{
  const r=structuredClone(record),t=r.targets![0]!;t.execution_revision=2;t.state='active';t.run={id:'run_canary',plan_revision:2,spec:{...t.spec,enabled:true},created_by:principal.id,state:'validating',code:'',stage:0,tasks:['task_validate','','',''],expected_sha256:'b'.repeat(64),created_at:at,expires_at:r.expires_at};expect(validRollout(r,true)).toBe(true)
  t.run.created_by='other';expect(validRollout(r,true)).toBe(false);t.run.created_by=principal.id;t.run.plan_revision=1;expect(validRollout(r,true)).toBe(false)
 })
})

describe('分批发布读取和原提交核对',()=>{
 it('详情核对后的状态同步回目录，返回时不恢复旧阶段',async()=>{
  const other={...record,id:'rollout_z'};request.mockResolvedValueOnce({items:[record,other],next_cursor:''});const{state}=host();await flushPromises()
  const completed={...record,state:'blocked',code:'deadline_exceeded',finished_at:'2026-10-18T06:10:00Z',targets:record.targets!.map(t=>({...t,state:'stopped',code:'not_dispatched'}))}
  request.mockResolvedValueOnce(completed);await state.show(record.id);state.back();expect(state.page.value.items[0]?.state).toBe('blocked');expect(state.page.value.items[0]?.code).toBe('deadline_exceeded');expect(state.page.value.items[0]?.targets).toBeUndefined();expect(state.page.value.items[1]).toEqual(other)
 })
 it('目录有界分页，拒绝重复、倒退与错误游标',async()=>{
  request.mockResolvedValueOnce({items:[record],next_cursor:record.id});const{state}=host();await flushPromises();request.mockResolvedValueOnce({items:[],next_cursor:''});state.next();await flushPromises();expect(request.mock.lastCall?.[0]).toContain('cursor=rollout_office');state.previous();await flushPromises();state.previous()
  for(const p of [{},{items:[record,record],next_cursor:''},{items:[record],next_cursor:'foreign'},{items:[{}],next_cursor:''},{items:[],next_cursor:2}]){request.mockResolvedValueOnce(p);await state.refresh();expect(state.error.value).toContain('完整')}
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('分批发布目录读取失败');request.mockRejectedValueOnce(new Error('读取超时'));await state.refresh();expect(state.error.value).toBe('读取超时')
 })
 it('详情独立读取并清除旧记录，关闭和卸载取消迟到响应',async()=>{
  const{state,wrapper}=host();await flushPromises();await state.show(record.id);expect(state.detail.value?.id).toBe(record.id)
  request.mockResolvedValueOnce({...record,id:'foreign'});await state.show(record.id);expect(state.detail.value).toBeUndefined();expect(state.detailError.value).toContain('完整')
  request.mockRejectedValueOnce('offline');await state.show(record.id);expect(state.detailError.value).toContain('详情读取失败')
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const showing=state.show(record.id);const signal=request.mock.lastCall?.[1].signal as AbortSignal;state.back();waiting.resolve(record);await showing;expect(signal.aborted).toBe(true);expect(state.detailID.value).toBe('')
  wrapper.unmount();const n=request.mock.calls.length;await state.refresh();await state.show(record.id);await state.loadPlans();await state.create(input);expect(request).toHaveBeenCalledTimes(n)
 })
 it('只逐页加载选择项，保留完整性错误，不自动猜测全量目录',async()=>{
  const{state}=host();await flushPromises();request.mockResolvedValueOnce({items:[plans[0]],next_cursor:plans[0]!.id});await state.loadPlans();expect(state.plans.value).toHaveLength(1)
  request.mockResolvedValueOnce({items:[plans[1]],next_cursor:''});await state.loadPlans(true);expect(state.plans.value).toHaveLength(2)
  request.mockResolvedValueOnce({items:[plans[1]],next_cursor:''});await state.loadPlans(true);expect(state.plansError.value).toContain('完整')
  request.mockRejectedValueOnce('offline');await state.loadPlans();expect(state.plansError.value).toContain('读取失败')
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const loading=state.loadPlans();await state.loadPlans();state.close();waiting.resolve({items:plans,next_cursor:''});await loading;expect(state.plans.value).toEqual([])
 })
 it('未知创建冻结输入，错误回执不能解除锁定，核对仍用原标识',async()=>{
  const{state}=host();await flushPromises();state.open();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));await state.create(input);expect(state.unconfirmed.value?.kind).toBe('create')
  await state.create({...input,spec:{...input.spec,name:'其他名称'}});expect(state.formError.value).toContain('原提交');state.open();expect(state.creating.value).toBe(true)
  request.mockResolvedValueOnce({...record,spec:{...record.spec,batch_size:1}});await state.create(input);expect(state.formError.value).toContain('原提交')
  request.mockResolvedValueOnce(record);state.confirm();await flushPromises();expect(state.unconfirmed.value).toBeUndefined();expect(state.creating.value).toBe(false);expect(state.detail.value?.id).toBe(record.id)
  const posts=request.mock.calls.filter(c=>c[1]?.method==='POST');expect(posts).toHaveLength(3);expect(posts.every(c=>JSON.stringify(c[1].body)===JSON.stringify(input))).toBe(true)
  state.confirm();await state.create({...input,id:''});expect(state.formError.value).toContain('标识')
 })
 it('明确拒绝允许修正；提交中禁止重复与关闭，身份变化清理原请求',async()=>{
  const{state}=host();await flushPromises();state.open();await flushPromises();request.mockRejectedValueOnce(new ApiError(409,'conflict','计划修订冲突'));await state.create(input);expect(state.unconfirmed.value).toBeUndefined()
  request.mockRejectedValueOnce(new ApiError(503,'rule_rollout_unavailable','执行服务未配置'));await state.create(input);expect(state.unconfirmed.value).toBeUndefined()
  request.mockRejectedValueOnce('offline');await state.create(input);expect(state.formError.value).toBe('分批发布操作失败')
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const action=state.create(input);await state.create(input);state.close();expect(state.creating.value).toBe(true)
  const signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,role:'viewer'};await flushPromises();waiting.resolve(record);await action;expect(signal.aborted).toBe(true);expect(state.unconfirmed.value).toBeUndefined();expect(state.page.value.items).toEqual([]);const n=request.mock.calls.length;await state.refresh();await state.show(record.id);await state.loadPlans();await state.create(input);state.open();expect(request).toHaveBeenCalledTimes(n)
 })
 it('停止使用独立原因和原对象核对，不能用成功发布回执冒充停止',async()=>{
  const{state}=host();await flushPromises();state.openStop();expect(state.stopping.value).toBe(false);await state.show(record.id);state.openStop();expect(state.stopping.value).toBe(true)
  await state.stop('');expect(state.formError.value).toContain('停止原因');request.mockRejectedValueOnce(new Error('中断'));await state.stop('现场维护');expect(state.unconfirmed.value).toMatchObject({kind:'stop',reason:'现场维护'})
  request.mockResolvedValueOnce(record);state.confirm();await flushPromises();expect(state.formError.value).toContain('原提交')
  const stopped={...record,state:'stopping',code:'operator_stopped',stop_reason:'现场维护',stopped_by:principal.id};request.mockResolvedValueOnce(stopped);state.confirm();await flushPromises();expect(state.unconfirmed.value).toBeUndefined();expect(state.detail.value?.state).toBe('stopping');expect(state.stopping.value).toBe(false)
 })
})

describe('分批发布表单与独立详情',()=>{
 it('表单逐项校验并冻结修订，首批顺序与明确授权可核对',async()=>{
  const wrapper=mount(RuleRolloutForm,{props:props(),global:{plugins:[registerAnt]},attachTo:document.body});await click('批准并启动');expect(document.body.textContent).toContain('发布名称')
  const name=document.querySelector<HTMLInputElement>('input[aria-label="发布名称"]')!;name.value=input.spec.name;name.dispatchEvent(new Event('input',{bubbles:true}));await wrapper.getComponent(Select).setValue(plans.map(p=>p.id),'value');await flushPromises();await click('批准并启动');expect(document.body.textContent).toContain('请确认固定范围')
  await wrapper.getComponent(Checkbox).setValue(true,'checked');await click('批准并启动');expect(wrapper.emitted('save')?.[0]?.[0]).toMatchObject({spec:{name:input.spec.name,plans:input.spec.plans,canary_count:1,batch_size:10,observation_seconds:60,timeout_seconds:3600}})
  expect(document.querySelector('.ant-modal-footer')?.textContent).toContain('批准并启动');expect(document.querySelector('.rollout-order')?.textContent).toContain('首批')
  await wrapper.setProps({hasMore:true});await click('加载更多计划');expect(wrapper.emitted('more')).toHaveLength(1);await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('混合规则阻止提交，读取失败和未知提交各有核对入口',async()=>{
  const changed=plans.map((p,i)=>i?{...p,spec:{...p.spec,package_revision:p.spec.package_revision+1}}:p);const wrapper=mount(RuleRolloutForm,{props:{...props(),plans:changed},global:{plugins:[registerAnt]},attachTo:document.body});const name=document.querySelector<HTMLInputElement>('input[aria-label="发布名称"]')!;name.value='混合计划';name.dispatchEvent(new Event('input',{bubbles:true}));await wrapper.getComponent(Select).setValue(plans.map(p=>p.id),'value');await click('批准并启动');expect(document.body.textContent).toContain('相同规则包修订')
  await wrapper.setProps({plansError:'读取失败'});await click('重试读取');expect(wrapper.emitted('retry')).toHaveLength(1);document.querySelector('form')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));expect(wrapper.emitted('save')).toBeUndefined()
  await wrapper.setProps({plansError:'',locked:true});expect(wrapper.findAllComponents(InputNumber).every(c=>c.find('input').attributes('disabled')!==undefined)).toBe(true);await click('核对原提交');expect(wrapper.emitted('confirm')).toHaveLength(1)
 })
 it('选择框 Esc 保留草稿，目标证据只展示一张业务表',async()=>{
  const wrapper=mount(RuleRolloutForm,{props:props(),global:{plugins:[registerAnt]},attachTo:document.body});const select=wrapper.getComponent(Select);await select.find('.ant-select-selector').trigger('mousedown');const event=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(event,'which',{value:27});select.find('input').element.dispatchEvent(event);await flushPromises();expect(wrapper.emitted('close')).toBeUndefined();wrapper.unmount()
  const router=createRouter({history:createMemoryHistory(),routes:[{path:'/',component:{render:()=>h('div')}},{path:'/sensors',component:{render:()=>h('div')}}]});await router.push('/');await router.isReady();const r=structuredClone(record);const t=r.targets![0]!;t.execution_revision=2;t.state='active';t.run={id:'run_canary',plan_revision:2,spec:{...t.spec,enabled:true},created_by:principal.id,state:'validating',code:'',stage:0,tasks:['task_validate','','',''],expected_sha256:'b'.repeat(64),created_at:at,expires_at:r.expires_at}
  const detail=mount(RuleRolloutDetail,{props:{rollout:r},global:{plugins:[registerAnt,router]},attachTo:document.body});expect(detail.findAll('.ant-table')).toHaveLength(1);await click('验证证据');expect(detail.findAll('.ant-table')).toHaveLength(0);expect(document.querySelector('a[href="/sensors?view=tasks&task=task_validate"]')).not.toBeNull();await detail.setProps({taskPath:"/page/rule-tests"});expect(document.querySelector('a[href="/page/rule-tests?view=tasks&task=task_validate"]')).not.toBeNull();detail.getComponent(Modal).vm.$emit('cancel');await flushPromises();expect(detail.findAll('.ant-table')).toHaveLength(1)
 })
 it('列表、详情、停止与无数据各自独立展示，刷新失败保留真实错误',async()=>{
  const wrapper=await view();expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('查看');expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(wrapper.text()).toContain('当前批次');await click('停止后续发布');await click('确认停止后续发布');expect(document.body.textContent).toContain('请填写 1–512 字的停止原因');wrapper.getComponent(Modal).vm.$emit('cancel');await flushPromises();await click('返回列表');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  await click('创建分批发布');expect(wrapper.findComponent(RuleRolloutForm).exists()).toBe(true);wrapper.getComponent(RuleRolloutForm).vm.$emit('close');await flushPromises();request.mockResolvedValueOnce({items:[],next_cursor:''});await click('刷新');expect(wrapper.text()).toContain('暂无分批发布')
 })
})
