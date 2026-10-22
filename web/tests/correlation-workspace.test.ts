import {webcrypto,randomUUID} from 'node:crypto'
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {createRouter,createMemoryHistory} from 'vue-router'
import {Form} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {ApiError} from '../packages/shared/src/api'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {useCorrelationRules} from '../platform/src/features/correlation/useCorrelationRules'
import CorrelationCatalog from '../platform/src/features/correlation/CorrelationCatalog.vue'
import CorrelationBacktest from '../platform/src/features/correlation/CorrelationBacktest.vue'
import CorrelationView from '../platform/src/views/CorrelationView.vue'
import CorrelationRuleForm from '../packages/shared/src/components/CorrelationRuleForm.vue'
import CorrelationRuleDetail from '../packages/shared/src/components/CorrelationRuleDetail.vue'
import CorrelationScopeForm from '../packages/shared/src/components/CorrelationScopeForm.vue'
import {definitionShape,type CorrelationChange} from '../packages/shared/src/correlation'
import {correlationRule as rule,correlationQuery as query,correlationResult as result,correlationEmpty as empty} from './correlation-fixture'
import {principal,click,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal),wrappers:VueWrapper[]=[]
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const body=()=>new DOMWrapper(document.body)
const input=():CorrelationChange=>({id:rule.id,expected_revision:0,name:rule.name,description:rule.description,active:rule.active,definition:definitionShape(rule.definition)})
const page={items:[rule],next_cursor:''}
function host(){let state!:ReturnType<typeof useCorrelationRules>;const wrapper=mount(defineComponent({setup(){state=useCorrelationRules();return()=>h('div')}}));wrappers.push(wrapper);return {state,wrapper}}
function good(){request.mockImplementation(async(path:string,options?:{method?:string})=>path.includes('/revisions/')?rule:path.endsWith('/backtest')?result:options?.method==='POST'?rule:page)}
async function screen(component:Parameters<typeof mount>[0],path='/detection/correlation/rules'){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/detection/correlation/rules',component:CorrelationCatalog,meta:{workspaceView:'rules',viewPaths:{rules:'/detection/correlation/rules',backtest:'/detection/correlation/backtest'}}},{path:'/detection/correlation/backtest',component:CorrelationBacktest,meta:{workspaceView:'backtest',viewPaths:{rules:'/detection/correlation/rules',backtest:'/detection/correlation/backtest'}}}]});await router.push(path);await router.isReady();const w=mount(component,{attachTo:document.body,global:{plugins:[registerAnt,router]}});wrappers.push(w);await flushPromises();await vi.waitFor(()=>expect(w.find('.ant-spin-spinning').exists()).toBe(false));return {w,router}
}
async function run(w:VueWrapper){w.getComponent(CorrelationScopeForm).vm.$emit('run',query);await flushPromises()}
beforeEach(()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID});vi.spyOn(Date,'now').mockReturnValue(Date.parse('2026-10-22T00:00:00Z'));good()})
afterEach(()=>{vi.useRealTimers();wrappers.splice(0).forEach(w=>w.unmount());document.body.innerHTML='';vi.unstubAllGlobals()})

describe('关联目录读取与原提交恢复',()=>{
 it('筛选与分页核对同一查询范围，迟到读取和账号切换不会覆盖当前目录',async()=>{
  const items=Array.from({length:20},(_,n)=>({...rule,id:'correlation_'+String(n).padStart(2,'0')})),q={cursor:'',keyword:'',active:'',limit:20},raw=JSON.stringify({after:items.at(-1)!.id,scope:await goJSONDigest({tenant:rule.tenant_id,query:q})}),next=btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
  request.mockResolvedValue({items,next_cursor:next});const {state,wrapper}=host();await vi.waitFor(()=>expect(state.page.value.items).toHaveLength(20));request.mockResolvedValue({items:[],next_cursor:''});state.next();await vi.waitFor(()=>expect(state.pending.value).toBe(false));expect(state.cursors.value).toHaveLength(2);state.previous();await vi.waitFor(()=>expect(state.pending.value).toBe(false));expect(state.cursors.value).toEqual(['']);state.search('  同源  ','true');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('active=true');expect(state.keyword.value).toBe('同源')
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.search('其他','');await flushPromises();expect(signal.aborted).toBe(true);old.resolve(page);await reading;expect(state.page.value.items).toEqual([])
  user.value={...principal,csrf_token:'changed'};await flushPromises();expect(state.cursors.value).toEqual(['']);expect(state.keyword.value).toBe('')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const last=state.refresh();wrapper.unmount();late.resolve(page);await last;await state.refresh();expect(state.page.value.items).toEqual([])
 })
 it('损坏目录、非 Error 异常和未取得下一页均不显示成功或推进页码',async()=>{
  request.mockResolvedValue({});const {state}=host();await flushPromises();expect(state.error.value).toContain('不一致');state.next();state.previous();expect(state.cursors.value).toEqual(['']);request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('关联规则读取失败。')
 })
 it('未知保存保留相同输入和请求键，核对操作者及原回执后完成',async()=>{
  const {state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('连接中断'));expect(await state.save(input())).toBeUndefined();expect(state.unconfirmed.value).toBe(true);const original=request.mock.lastCall?.[1];state.clearError();expect(state.mutationError.value).toBe('连接中断');expect(state.draft()).toEqual(input());expect(await state.save({...input(),name:'其他'})).toBeUndefined();expect(state.mutationError.value).toContain('原提交')
  request.mockResolvedValueOnce({...rule,created_by:'other'});expect(await state.confirm()).toBeUndefined();expect(state.unconfirmed.value).toBe(true);request.mockResolvedValueOnce(rule);expect(await state.confirm()).toEqual(rule);expect(request.mock.lastCall?.[1].headers).toEqual(original.headers);expect(request.mock.lastCall?.[1].body).toEqual(original.body);expect(state.unconfirmed.value).toBe(false);expect(state.draft()).toBeUndefined();expect(await state.confirm()).toBeUndefined();state.clearError();expect(state.mutationError.value).toBe('');expect(await state.save({...input(),name:''})).toBeUndefined();expect(state.mutationError.value).toContain('名称')
 })
 it('明确冲突允许重新编辑，超时、并发提交和卸载保留未知边界',async()=>{
  const {state,wrapper}=host();await flushPromises();request.mockRejectedValueOnce(new ApiError(409,'conflict','修订变化'));expect(await state.save(input())).toBeUndefined();expect(state.unconfirmed.value).toBe(false)
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);vi.useFakeTimers();const saving=state.save(input());expect(await state.save(input())).toBeUndefined();await vi.advanceTimersByTimeAsync(30001);waiting.resolve(rule);await saving;vi.useRealTimers();expect(state.unconfirmed.value).toBe(true);expect(state.mutationError.value).toContain('确认')
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const confirming=state.confirm();const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(rule);await confirming;expect(await state.save(input())).toBeUndefined()
 })
 it('写入期间账号切换不会接受旧回执，新的身份清空原提交',async()=>{
  const {state}=host();await flushPromises();const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);const writing=state.save(input());const signal=request.mock.lastCall?.[1].signal as AbortSignal;user.value={...principal,tenant_id:'other'};await flushPromises();expect(signal.aborted).toBe(true);waiting.resolve(rule);await writing;expect(state.unconfirmed.value).toBe(false);expect(state.draft()).toBeUndefined()
 })
})

describe('关联目录与窗口回测页面',()=>{
 it('查看与历史读取独立，详情失败不保留旧版本，关闭取消读取',async()=>{
  const {w}=await screen(CorrelationCatalog);expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);await click('查看');await vi.waitFor(()=>expect(body().text()).toContain('定义 SHA-256'));request.mockResolvedValueOnce({...rule,id:'other'});w.getComponent(CorrelationRuleDetail).vm.$emit('read',1);await flushPromises();await vi.waitFor(()=>expect(body().text()).toContain('所选记录不一致'));expect(body().text()).not.toContain(rule.definition_sha256);const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);w.getComponent(CorrelationRuleDetail).vm.$emit('read',1);await flushPromises();const signal=request.mock.lastCall?.[1].signal as AbortSignal;await click('关闭');expect(signal.aborted).toBe(true);late.resolve(rule);await flushPromises();expect(w.findComponent(CorrelationRuleDetail).exists()).toBe(false)
 })
 it('未知原提交关闭后可以重新核对，同一请求确认后关闭表单',async()=>{
  const {w}=await screen(CorrelationCatalog);await click('创建关联规则');request.mockRejectedValueOnce(new Error('未收到回执'));w.getComponent(CorrelationRuleForm).vm.$emit('save',input());await flushPromises();expect(body().text()).toContain('未收到回执');await click('关闭');await click('核对原提交');await click('核对原提交',document.querySelector('.ant-modal')!);await vi.waitFor(()=>expect(w.findComponent(CorrelationRuleForm).exists()).toBe(false))
 })
 it('编辑与固定修订跳转分别保持所选规则身份',async()=>{
  const {w,router}=await screen(CorrelationCatalog);await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1));await click('编辑');expect(body().text()).toContain('编辑关联规则');await click('关闭');await click('窗口回测');expect(router.currentRoute.value.path).toBe('/detection/correlation/backtest');expect(router.currentRoute.value.query).toEqual({rule_id:rule.id,revision:'1'})
 })
 it('名称筛选、重置与刷新使用当前目录条件，仍保持单一表格',async()=>{
  const {w}=await screen(CorrelationCatalog);await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1));await w.get('input[aria-label="筛选关联规则名称"]').setValue('同源');await w.get('form').trigger('submit');expect(request.mock.calls.some(c=>String(c[0]).includes('keyword='))).toBe(true);await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1));await click('重置');await click('刷新目录');await vi.waitFor(()=>expect(w.findAll('.ant-table-wrapper')).toHaveLength(1))
 })
 it('只读角色可读目录，无创建或编辑入口；管理员页签按规范路径切换',async()=>{
  user.value={...principal,role:'viewer'};const {w}=await screen(CorrelationView);expect(w.text()).not.toContain('创建关联规则');expect(w.text()).not.toContain('编辑');expect(w.get('nav[aria-label="检测规则功能"]').findAll('[role=tab]').map(tab=>tab.text())).toEqual(['规则包','应用识别规则','关联规则']);user.value=principal;await flushPromises();expect(w.get('nav[aria-label="检测规则功能"]').text()).toContain('窗口回测')
 })
 it('未选择、参数异常、错修订与不可用版本均不给予可执行结果',async()=>{
  const {w,router}=await screen(CorrelationBacktest,'/detection/correlation/backtest');expect(w.text()).toContain('请从关联规则目录选择');await router.push('/detection/correlation/backtest?rule_id=x&revision=01');await flushPromises();expect(w.text()).toContain('选择参数无效');request.mockResolvedValueOnce({...rule,revision:2});await router.push('/detection/correlation/backtest?rule_id='+rule.id+'&revision=1');await flushPromises();await vi.waitFor(()=>expect(w.text()).toContain('当前选择不一致'));request.mockResolvedValueOnce({...rule,active:false});await router.push('/detection/correlation/backtest?rule_id='+rule.id+'&revision=2');await flushPromises();await vi.waitFor(()=>expect(w.text()).toContain('当前选择不一致'));request.mockResolvedValueOnce({...rule,active:false});await router.push('/detection/correlation/backtest?rule_id='+rule.id+'&revision=1');await flushPromises();await vi.waitFor(()=>expect(w.text()).toContain('所选修订已停用'));await run(w);expect(request.mock.calls.filter(c=>String(c[0]).endsWith('/backtest'))).toHaveLength(0)
 })
 it('真实结果核对后展示一张窗口表格，修改条件清除旧结论与迟到请求',async()=>{
  const {w}=await screen(CorrelationBacktest,'/detection/correlation/backtest?rule_id='+rule.id+'&revision=1');await run(w);await vi.waitFor(()=>expect(w.text()).toContain(result.snapshot_sha256));expect(w.findAll('.ant-table-wrapper')).toHaveLength(1);expect(w.text()).toContain('已观察到阈值');w.getComponent(CorrelationScopeForm).vm.$emit('change');await flushPromises();expect(w.text()).not.toContain(result.snapshot_sha256)
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);await run(w);const signal=request.mock.lastCall?.[1].signal as AbortSignal;w.getComponent(CorrelationScopeForm).vm.$emit('change');await flushPromises();expect(signal.aborted).toBe(true);old.resolve(result);await flushPromises();expect(w.text()).not.toContain(result.snapshot_sha256)
  request.mockResolvedValueOnce(empty);await run(w);expect(w.text()).toContain('不代表流量安全')
 })
 it('停止等待、冲突、无效回执与重选规则不会混用旧结果',async()=>{
  const {w,router}=await screen(CorrelationBacktest,'/detection/correlation/backtest?rule_id='+rule.id+'&revision=1');const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);await run(w);const signal=request.mock.lastCall?.[1].signal as AbortSignal;await click('停止等待');expect(signal.aborted).toBe(true);waiting.resolve(result);await flushPromises();expect(w.text()).toContain('已停止等待');expect(w.text()).not.toContain(result.snapshot_sha256)
  request.mockRejectedValueOnce(new ApiError(409,'conflict','规则已停用'));await run(w);expect(w.text()).toContain('当前状态与修订');request.mockResolvedValueOnce({});await run(w);expect(w.text()).toContain('不一致');await click('返回规则目录');expect(router.currentRoute.value.path).toBe('/detection/correlation/rules')
 })
 it('无效范围、超时与页面卸载不会交付部分结果',async()=>{
  const {w}=await screen(CorrelationBacktest,'/detection/correlation/backtest?rule_id='+rule.id+'&revision=1');w.getComponent(CorrelationScopeForm).vm.$emit('run',{...query,start:query.end});await flushPromises();expect(w.text()).toContain('单次范围');const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);vi.useFakeTimers();const running=run(w);await vi.advanceTimersByTimeAsync(55001);late.reject(new Error('timeout'));await running;await flushPromises();vi.useRealTimers();expect(w.text()).toContain('回测等待超时');const lost=deferred<unknown>();request.mockReturnValueOnce(lost.promise);await run(w);const signal=request.mock.lastCall?.[1].signal as AbortSignal;w.unmount();expect(signal.aborted).toBe(true);lost.resolve(result);await flushPromises();expect(body().text()).not.toContain(result.snapshot_sha256)
 })
})
