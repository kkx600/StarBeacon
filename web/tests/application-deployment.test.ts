import {webcrypto,randomUUID} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import {principal,deferred} from './fixtures'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {basicApplicationState,validApplicationState,validApplicationAttribution,type ApplicationAttribution,type ApplicationState} from '../packages/shared/src/application'
import ApplicationAttributionView from '../packages/shared/src/components/ApplicationAttribution.vue'
import {applicationTargets,deploymentTargetFresh,validAppSnapshot,type AppSnapshot} from '../platform/src/features/applications/applicationDeployment'
import {useApplicationDeployment} from '../platform/src/features/applications/useApplicationDeployment'
import ApplicationDeploymentForm from '../platform/src/features/applications/ApplicationDeploymentForm.vue'
import ApplicationRulesWorkspace from '../platform/src/features/applications/ApplicationRulesWorkspace.vue'
const {request,push}=vi.hoisted(()=>({request:vi.fn(),push:vi.fn()}))
const user=shallowRef<typeof principal|null>(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
vi.mock('../platform/src/router',()=>({router:{push}}))
async function state(id='',rules?:string,count=0):Promise<ApplicationState>{rules??=await goJSONDigest([]);return {schema_version:'application-state.v1',deployment_id:id,rules_sha256:rules,state_sha256:await goJSONDigest({deployment_id:id,rules_sha256:rules}),rule_count:count,installed_at:id?new Date().toISOString():null}}
async function snapshot():Promise<AppSnapshot>{const versions:AppSnapshot['versions']=[{id:'rule_files',revision:1,definition:{schema_version:'application-rule.v1',product_id:'owned_files',product_name:'业务文件服务',category_id:'cloud_storage',protocols:['http'],any:[{field:'http.host',op:'domain_suffix',value:'files.example'}],all:[],exclude:[]}}];return {versions,rules_sha256:await goJSONDigest(versions)}}
async function sensors(){return {items:[{id:'sensor_owned',name:'业务探针',registration_id:'reg_owned',status:'online',active:true,health:{observed_at:new Date().toISOString(),task_capabilities:['applications.apply'],application_rules:await state()}}]}}
async function sources(){const s=await snapshot(),probes=await sensors();request.mockImplementation((path:string)=>Promise.resolve(path==='/application-rules/snapshot'?s:path==='/sensors'?probes:{id:'task_owned'}));return {s,probes}}
function host(){let model!:ReturnType<typeof useApplicationDeployment>;const wrapper=mount(defineComponent({setup(){model=useApplicationDeployment();return()=>h('div')}}));return {model,wrapper}}
function ui(component:Parameters<typeof mount>[0],props:Record<string,unknown>={}):VueWrapper<any>{return mount(component,{props,attachTo:document.body,global:{plugins:[{install:registerAnt}]}}) as VueWrapper<any>}
const body=()=>new DOMWrapper(document.body)
async function click(text:string){const button=body().findAll('button').find(row=>row.text().replace(/\s/g,'')===text);if(!button)throw new Error('没有按钮：'+text);await button.trigger('click');await flushPromises()}
async function ready(model:ReturnType<typeof useApplicationDeployment>){model.show();await vi.waitFor(()=>expect(model.snapshot.value).not.toBeNull());model.choose('sensor_owned')}
function attribution():ApplicationAttribution {return {schema_version:'application-attribution.v1',deployment_id:'task_owned',state_sha256:'2'.repeat(64),raw_sha256:'1'.repeat(64),product_id:'owned_files',product_name:'业务文件服务',category_id:'cloud_storage',result:{schema_version:'application-test.v1',origin:'suricata_visible_metadata',protocol:'http',status:'candidate',reason:'visible_name_rule',evaluated_at:'2026-10-14T01:00:00.123456789Z',observation_sha256:'3'.repeat(64),rules_sha256:'4'.repeat(64),rule_count:1,matched_rule_count:1,matches:[{rule_id:'rule_files',revision:1,product_id:'owned_files',product_name:'业务文件服务',category_id:'cloud_storage',evidence:[{field:'http.host',op:'domain_suffix',pattern:'files.example'}],evidence_limited:false}],limited:false}}}
beforeEach(()=>{request.mockReset();push.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID})})

describe('应用部署与实际分类契约',()=>{
 it('核对初始和生效状态的独立摘要，拒绝损坏注册状态',async()=>{
  const empty=await state(),active=await state('task_owned','1'.repeat(64),1)
  expect(basicApplicationState(empty)).toBe(true);expect(await validApplicationState(empty)).toBe(true);expect(await validApplicationState(active)).toBe(true)
  for(const value of [null,{}, {...empty,schema_version:'bad'},{...empty,rule_count:129},{...empty,deployment_id:'/'},{...empty,installed_at:'2026-10-14T00:00:00Z'},{...active,installed_at:null},{...active,installed_at:'invalid'},{...active,state_sha256:'0'.repeat(64)},{...empty,rules_sha256:'1'.repeat(64)}])expect(await validApplicationState(value)).toBe(false)
 })
 it('完整目录排序、修订、定义与摘要必须一致',async()=>{
  const s=await snapshot();expect(await validAppSnapshot(s)).toBe(true);expect(await validAppSnapshot({versions:[],rules_sha256:await goJSONDigest([])})).toBe(true)
  for(const value of [null,{}, {...s,rules_sha256:'0'.repeat(64)},{...s,versions:[s.versions[0],s.versions[0]]},{...s,versions:[{...s.versions[0],id:'/' }]},{...s,versions:[{...s.versions[0],revision:0}]},{...s,versions:[{...s.versions[0],definition:{}}]},{...s,versions:new Array(129).fill(s.versions[0])}])expect(await validAppSnapshot(value)).toBe(false)
 })
 it('只选择具备有效观测、代次和应用能力的在线探针',async()=>{
  const probes=await sensors(),row=probes.items[0]!,now=Date.now()
  expect(await applicationTargets(probes,now)).toHaveLength(1)
  for(const change of [{active:false},{status:'offline'},{health:{...row.health,task_capabilities:[]}},{health:{...row.health,observed_at:'bad'}},{health:{...row.health,observed_at:new Date(now-36000).toISOString()}},{health:{...row.health,observed_at:new Date(now+61000).toISOString()}},{health:{...row.health,application_rules:{}}}])expect(await applicationTargets({items:[{...row,...change}]},now)).toHaveLength(0)
  for(const value of [null,{}, {items:[row,row]},{items:[{...row,id:'/'}]},{items:[{...row,health:null}]},{items:new Array(10001).fill(row)}])await expect(applicationTargets(value)).rejects.toThrow('探针')
  const target=(await applicationTargets(probes,now))[0]!;expect(deploymentTargetFresh(target,now)).toBe(true);expect(deploymentTargetFresh(target,now+36000)).toBe(false)
 })
 it('分类绑定原文摘要与纳秒时间，缺测和冲突不能成为唯一产品',()=>{
  const a=attribution();expect(validApplicationAttribution(a,a.raw_sha256,a.result.evaluated_at)).toBe(true)
  for(const value of [null,{}, {...a,deployment_id:'/'},{...a,raw_sha256:'0'.repeat(64)},{...a,product_id:'other'},{...a,result:{...a.result,origin:'user_supplied_metadata'}},{...a,result:{...a.result,status:'confirmed'}},{...a,result:{...a.result,evaluated_at:'2026-10-14T01:00:00.123456788Z'}},{...a,result:{...a.result,matches:[]}},{...a,result:{...a.result,limited:true}},{...a,result:{...a.result,matches:[{...a.result.matches[0],evidence:[]}]}},{...a,result:{...a.result,matches:[{...a.result.matches[0],evidence:[{field:'tls.body',op:'eq',pattern:'plaintext'}]}]}}])expect(validApplicationAttribution(value,a.raw_sha256,a.result.evaluated_at)).toBe(false)
  const unknown:ApplicationAttribution={...a,product_id:'',product_name:'',category_id:'',result:{...a.result,status:'unknown',reason:'transaction_unbound',matched_rule_count:0,matches:[]}}
  expect(validApplicationAttribution(unknown,a.raw_sha256,a.result.evaluated_at)).toBe(true);expect(validApplicationAttribution({...unknown,product_name:'推测产品'},a.raw_sha256,a.result.evaluated_at)).toBe(false)
  const conflict:ApplicationAttribution={...unknown,result:{...a.result,status:'conflict',reason:'multiple_products',rule_count:2,matched_rule_count:2,matches:[a.result.matches[0]!,{...a.result.matches[0]!,rule_id:'other_rule',product_id:'other_product'}]}}
  expect(validApplicationAttribution(conflict,a.raw_sha256,a.result.evaluated_at)).toBe(true);expect(validApplicationAttribution({...conflict,result:{...conflict.result,matches:[a.result.matches[0]!,a.result.matches[0]!]}},a.raw_sha256,a.result.evaluated_at)).toBe(false)
 })
 it('详情展示正向依据、输出限制和明确的事实边界',async()=>{
  const a=attribution(),w=ui(ApplicationAttributionView,{attribution:a,rawDigest:a.raw_sha256,observed:a.result.evaluated_at});expect(w.text()).toContain('业务文件服务');expect(w.text()).toContain('规则候选');expect(w.text()).toContain('通信字节数')
  await w.setProps({attribution:{...a,result:{...a.result,matched_rule_count:20,rule_count:20,matches:Array.from({length:16},(_,i)=>({...a.result.matches[0],rule_id:'rule_'+i,evidence_limited:true})),limited:true}}});expect(w.text()).toContain('前 16 条');expect(w.text()).toContain('展示预算')
  await w.setProps({attribution:{...a,raw_sha256:'bad'}});expect(w.text()).toContain('不完整');expect(w.text()).not.toContain('业务文件服务')
  await w.setProps({attribution:undefined});expect(w.text()).toContain('未提供可核验');w.unmount()
 })
})

describe('应用规则部署原提交与生命周期',()=>{
 it('完整读取分页后的可执行探针，目录重复或游标失效不得显示截断选项',async()=>{
  const s=await snapshot(),row=(await sensors()).items[0]!,first=Array.from({length:100},(_,i)=>({...row,id:'sensor_'+String(i).padStart(4,'0'),status:'offline'}))
  request.mockImplementation((path:string)=>Promise.resolve(path==='/application-rules/snapshot'?s:path==='/sensors'?{items:first,next_cursor:'sensor_0099'}:{items:[row],next_cursor:''}))
  const {model,wrapper}=host();model.show();await vi.waitFor(()=>expect(model.pending.value).toBe(false));expect(model.targets.value.map(r=>r.id)).toEqual(['sensor_owned']);expect(request.mock.calls.some(call=>call[0]==='/sensors?cursor=sensor_0099&limit=100')).toBe(true)
  request.mockImplementation((path:string)=>Promise.resolve(path==='/application-rules/snapshot'?s:path==='/sensors'?{items:[row],next_cursor:row.id}:{items:[row],next_cursor:''}))
  await model.refresh();expect(model.targets.value).toEqual([]);expect(model.snapshot.value).toBeNull();expect(model.error.value).toContain('完整返回');wrapper.unmount()
 })
 it('受理绑定原规则、注册代次与目标，确认后提供任务标识',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);const input={expected_registration_id:'reg_owned',expected_state_sha256:model.target.value!.state.state_sha256,rules_sha256:model.snapshot.value!.rules_sha256}
  await model.submit();expect(model.taskID.value).toBe('task_owned');expect(request.mock.lastCall?.[0]).toBe('/sensors/sensor_owned/application-rules');expect(request.mock.lastCall?.[1].body).toEqual(input);expect(request.mock.lastCall?.[1].headers['Idempotency-Key']).toMatch(/^[a-z0-9-]{36}$/);expect(model.unconfirmed.value).toBe(false);wrapper.unmount()
 })
 it('超时或网络未知保留原输入与键，关闭后仍可核对原提交',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);request.mockRejectedValueOnce(new ApiError(503,'storage_unavailable','服务暂不可用'));await model.submit();const first=request.mock.lastCall!
  expect(model.unconfirmed.value).toBe(true);model.choose('other_sensor');expect(model.selected.value).toBe('sensor_owned');const calls=request.mock.calls.length;await model.refresh();expect(request.mock.calls).toHaveLength(calls)
  model.hide();model.show();expect(model.open.value).toBe(true);expect(request.mock.calls).toHaveLength(calls)
  request.mockResolvedValueOnce({id:'task_recovered'});await model.confirm();expect(request.mock.lastCall?.[1].body).toEqual(first[1].body);expect(request.mock.lastCall?.[1].headers).toEqual(first[1].headers);expect(model.taskID.value).toBe('task_recovered');expect(model.unconfirmed.value).toBe(false);wrapper.unmount()
 })
 it('明确冲突不生成自动重试，过期观测须刷新后重选',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);request.mockRejectedValueOnce(new ApiError(409,'application_state_conflict','配置变化'));await model.submit();expect(model.unconfirmed.value).toBe(false);expect(model.error.value).toContain('配置变化');const n=request.mock.calls.length;await model.confirm();expect(request.mock.calls).toHaveLength(n)
  const target=model.target.value!;target.observed_at=new Date(Date.now()-36000).toISOString();await model.submit();expect(model.error.value).toContain('过期');expect(request.mock.calls).toHaveLength(n);wrapper.unmount()
 })
 it('拒绝回执假成功、等待时保留原窗口，未确认不能二次提交',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const submission=model.submit();await flushPromises();model.hide();expect(model.open.value).toBe(true);await model.submit();waiting.resolve({id:'../bad'});await submission;expect(model.unconfirmed.value).toBe(true);expect(model.taskID.value).toBe('');const count=request.mock.calls.length;await model.submit();expect(request.mock.calls).toHaveLength(count);wrapper.unmount()
 })
 it('会话变化或卸载终止等待，迟到回执不能进入其他账号',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const submission=model.submit();await flushPromises();const signal=request.mock.lastCall?.[1].signal as AbortSignal
  user.value={...principal,csrf_token:'changed'};await flushPromises();expect(signal.aborted).toBe(true);waiting.resolve({id:'late_task'});await submission;expect(model.open.value).toBe(false);expect(model.taskID.value).toBe('');wrapper.unmount()
  user.value=principal;await sources();const other=host();await ready(other.model);const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);const write=other.model.submit();await flushPromises();other.wrapper.unmount();pending.resolve({id:'late_after_unmount'});await write;expect(other.model.taskID.value).toBe('')
 })
 it('加载异常和摘要冲突不允许提交，读取超时有可重试状态',async()=>{
  const probes=await sensors();request.mockImplementation((path:string)=>Promise.resolve(path==='/sensors'?probes:{}));const {model,wrapper}=host();model.show();await vi.waitFor(()=>expect(model.pending.value).toBe(false));expect(model.error.value).toContain('快照');expect(model.snapshot.value).toBeNull();await model.submit();model.choose('missing');await model.submit()
  const waiting=deferred<unknown>();request.mockReturnValue(waiting.promise);vi.useFakeTimers();const load=model.refresh();await vi.advanceTimersByTimeAsync(30001);expect(model.pending.value).toBe(false);expect(model.error.value).toContain('超过期限');waiting.resolve({});await load;vi.useRealTimers();wrapper.unmount()
 })
 it('提交超时保留确认状态，权限撤回停止后续写入',async()=>{
  await sources();const {model,wrapper}=host();await ready(model);const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);vi.useFakeTimers();const submit=model.submit();await vi.advanceTimersByTimeAsync(30001);expect(model.busy.value).toBe(false);expect(model.unconfirmed.value).toBe(true);waiting.resolve({id:'late_task'});await submit;expect(model.taskID.value).toBe('');vi.useRealTimers()
  user.value={...principal,role:'viewer'};await flushPromises();const calls=request.mock.calls.length;model.show();await model.refresh();await model.submit();await model.confirm();expect(request.mock.calls).toHaveLength(calls);expect(model.open.value).toBe(false);wrapper.unmount()
 })
})

describe('应用部署表单和工作区入口',()=>{
 it('空快照、无目标、锁定与受理状态均展示明确业务含义',async()=>{
  const snapshot={versions:[],rules_sha256:await goJSONDigest([])},w=ui(ApplicationDeploymentForm,{pending:false,busy:false,unconfirmed:false,error:'',targets:[],snapshot,selected:'',taskId:''});await flushPromises();expect(body().text()).toContain('清空目标探针');expect(body().text()).toContain('没有符合条件');await click('刷新规则与探针');expect(w.emitted('refresh')).toHaveLength(1)
  await w.setProps({unconfirmed:true,error:'结果未知'});await click('核对原提交');expect(w.emitted('confirm')).toHaveLength(1);await w.setProps({unconfirmed:false,error:'',taskId:'task_owned'});await click('查看执行回执');expect(w.emitted('task')).toEqual([['task_owned']]);w.unmount()
 })
 it('工作区入口打开单一部署弹窗，关闭和返回不会遗留其他弹窗',async()=>{
  const s=await snapshot(),probes=await sensors();request.mockImplementation((path:string)=>Promise.resolve(path==='/application-rules'?{items:[],next_cursor:''}:path==='/application-rules/snapshot'?s:probes));const w=ui(ApplicationRulesWorkspace);await flushPromises();await click('部署到探针');await vi.waitFor(()=>expect(w.findComponent(ApplicationDeploymentForm).exists()).toBe(true));await vi.waitFor(()=>expect(w.findComponent(ApplicationDeploymentForm).props('pending')).toBe(false));w.findComponent(ApplicationDeploymentForm).vm.$emit('choose','sensor_owned');await flushPromises();request.mockResolvedValue({id:'task_owned'});w.findComponent(ApplicationDeploymentForm).vm.$emit('submit');await vi.waitFor(()=>expect(w.findComponent(ApplicationDeploymentForm).props('taskId')).toBe('task_owned'));w.findComponent(ApplicationDeploymentForm).vm.$emit('task','task_owned');await flushPromises();expect(push).toHaveBeenCalledWith({path:'/sensors',query:{view:'tasks',task:'task_owned'}});expect(w.findComponent(ApplicationDeploymentForm).exists()).toBe(false);w.unmount()
 })
})
