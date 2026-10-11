import {webcrypto,randomUUID} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef} from 'vue'
import {DOMWrapper,flushPromises,mount,type VueWrapper} from '@vue/test-utils'
import {Form,Select} from 'ant-design-vue'
import {ApiError} from '../packages/shared/src/api'
import {registerAnt} from '../packages/shared/src/ant'
import {principal,deferred} from './fixtures'
import {appDigest,conditionOperators,changeError,emptyObservation,orderedDefinition,orderedObservation,validDefinition,validRule,validRulePage,validRuleReceipt,validTestResult,type AppChange,type AppDefinition,type AppObservation,type AppPage,type AppResult,type AppRule} from '../platform/src/features/applications/applicationRules'
import {useApplicationRules} from '../platform/src/features/applications/useApplicationRules'
import ApplicationRuleForm from '../platform/src/features/applications/ApplicationRuleForm.vue'
import ApplicationRuleTest from '../platform/src/features/applications/ApplicationRuleTest.vue'
import ApplicationRulesWorkspace from '../platform/src/features/applications/ApplicationRulesWorkspace.vue'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const definition=():AppDefinition=>({schema_version:'application-rule.v1',product_id:'owned_files',product_name:'业务文件服务',category_id:'cloud_storage',protocols:['http','tls'],any:[{field:'http.host',op:'domain_suffix',value:'files.example'},{field:'tls.sni',op:'eq',value:'files.example'}],all:[],exclude:[]})
const input=():AppChange=>({id:'app_files',expected_revision:0,name:'业务文件服务名称规则',description:'可见域名验证',active:true,definition:definition()})
async function record(change=input()):Promise<AppRule>{return {tenant_id:user.value.tenant_id,id:change.id,revision:change.expected_revision+1,name:change.name,description:change.description,active:change.active,definition:change.definition,definition_sha256:await appDigest(orderedDefinition(change.definition)),created_by:user.value.id,created_at:'2026-10-10T00:00:00Z',expires_at:'2027-04-08T00:00:00Z'}}
async function result(o:AppObservation,d?:AppDefinition,status:AppResult['status']='candidate'):Promise<AppResult>{const chosen=d??definition(),ruleID=d?'candidate_rule':'app_files';return {schema_version:'application-test.v1',origin:'user_supplied_metadata',protocol:o.protocol,status,reason:status==='candidate'?'visible_name_rule':status==='conflict'?'multiple_products':'no_matching_rule',evaluated_at:'2026-10-10T00:00:00Z',observation_sha256:await appDigest(orderedObservation(o)),rules_sha256:await appDigest([{id:ruleID,revision:1,definition:orderedDefinition(chosen)}]),rule_count:1,matched_rule_count:status==='unknown'?0:1,matches:status==='unknown'?[]:[{rule_id:ruleID,revision:1,product_id:chosen.product_id,product_name:chosen.product_name,category_id:chosen.category_id,evidence:[{field:'http.host',op:'domain_suffix',pattern:'files.example'}],evidence_limited:false}],limited:false}}
function host<T>(factory:()=>T){let state!:T;const wrapper=mount(defineComponent({setup(){state=factory();return()=>h('div')}}));return {state,wrapper}}
const body=()=>new DOMWrapper(document.body)
function ui(component:Parameters<typeof mount>[0],props:Record<string,unknown>={}):VueWrapper<any>{return mount(component,{props,attachTo:document.body,global:{plugins:[{install:registerAnt}],stubs:{}}}) as VueWrapper<any>}
async function click(w:VueWrapper,text:string){const button=w.findAll('button').find(b=>b.text().replace(/\s/g,'')===text)??body().findAll('button').find(b=>b.text().replace(/\s/g,'')===text);if(button)await button.trigger('click');else if(text==='关闭'&&body().find('.ant-modal-close').exists())await body().find('.ant-modal-close').trigger('click');else throw new Error('未找到操作：'+text);await flushPromises()}
async function finish(wrapper:VueWrapper){await flushPromises();await wrapper.findComponent(Form).vm.$emit('finish',{});await flushPromises()}
async function settled(){await vi.waitFor(()=>expect(body().findAll('button').some(b=>b.classes().includes('ant-btn-loading'))).toBe(false));await flushPromises()}
beforeEach(()=>{request.mockReset();user.value=principal;vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID})})

describe('应用规则与材料契约',()=>{
 it('拒绝错误字段、协议、组合、标识和不可写修订',()=>{
  expect(validDefinition(definition())).toBe(true);expect(changeError(input())).toBe('')
  const bad:unknown[]=[null,{}, {...definition(),unexpected:true},{...definition(),protocols:[]},{...definition(),protocols:['http','http']},{...definition(),protocols:['tcp']},{...definition(),product_id:'a/b'},{...definition(),product_name:' '},{...definition(),category_id:'tcp'},{...definition(),any:[]},{...definition(),all:null},{...definition(),any:new Array(17).fill(definition().any[0])},{...definition(),exclude:new Array(32).fill(definition().any[0])},{...definition(),any:[{field:'http.user_agent',op:'contains',value:'Browser'}]},{...definition(),any:[{field:'http.host',op:'regex',value:'.*'}]},{...definition(),any:[{field:'http.host',op:'eq',value:'https://files.example'}]},{...definition(),protocols:['dns']},{...definition(),all:[{field:'http.method',op:'eq',value:'get'}]},{...definition(),all:[{field:'http.path',op:'prefix',value:'relative'}]},{...definition(),any:[definition().any[0],definition().any[0]]},{...definition(),all:[{field:'http.host',op:'eq',value:'files.example',name:'ignored'}]}]
  for(const value of bad)expect(validDefinition(value)).toBe(false)
  expect(conditionOperators('http.path')).toEqual(['eq','prefix']);expect(conditionOperators('http.user_agent')).toEqual(['eq','contains']);expect(conditionOperators('http.method')).toEqual(['eq'])
  for(const value of [{...input(),id:'/'},{...input(),expected_revision:1000000},{...input(),name:' '},{...input(),description:'a\nb'},{...input(),active:false}])expect(changeError(value)).not.toBe('')
  expect(changeError({...input(),definition:{...definition(),any:[]}})).toContain('产品')
 })
 it('独立核对定义摘要、租户、目录排序、游标和保存回执',async()=>{
  const owned=await record();expect(await validRule(owned,principal.tenant_id)).toBe(true)
  for(const value of [null,{}, {...owned,tenant_id:'other'},{...owned,revision:0},{...owned,id:'/'},{...owned,active:'true'},{...owned,definition_sha256:'0'.repeat(64)},{...owned,created_at:'invalid'},{...owned,expires_at:owned.created_at}])expect(await validRule(value,principal.tenant_id)).toBe(false)
  expect(await validRulePage({items:[owned],next_cursor:''},principal.tenant_id,'','')).toBe(true)
  for(const value of [null,{}, {items:[owned,owned],next_cursor:''},{items:[owned],next_cursor:'app_other'},{items:[owned],next_cursor:owned.id},{items:[{...owned,id:'a_first'},owned],next_cursor:''},{items:new Array(21).fill(owned),next_cursor:''}])expect(await validRulePage(value,principal.tenant_id,owned.id,'true')).toBe(false)
  expect(await validRulePage({items:[owned],next_cursor:owned.id},principal.tenant_id,'','',1)).toBe(true)
  expect(await validRulePage({items:[owned],next_cursor:''},principal.tenant_id,'','false')).toBe(false)
  expect(await validRuleReceipt(owned,principal.tenant_id,input())).toBe(true)
  for(const value of [{...owned,id:'app_other'},{...owned,revision:2},{...owned,name:'变更'},{...owned,description:'变更'},{...owned,active:false}])expect(await validRuleReceipt(value,principal.tenant_id,input())).toBe(false)
  const escaped={...definition(),product_name:'业务 <应用> & 名称\u2028'};expect(await appDigest(orderedDefinition(escaped))).toMatch(/^[a-f0-9]{64}$/)
  vi.stubGlobal('crypto',{randomUUID});await expect(validRule(owned,principal.tenant_id)).rejects.toThrow('浏览器无法核对')
 })
 it('拒绝材料摘要、规则快照、状态与命中计数不一致的回执',async()=>{
  const o={...emptyObservation(),http_host:'files.example'},d=definition(),report=await result(o,d)
  expect(await validTestResult(report,o,d)).toBe(true)
  for(const value of [null,{}, {...report,origin:'live_packet'},{...report,protocol:'tls'},{...report,status:'confirmed'},{...report,evaluated_at:'bad'},{...report,observation_sha256:'0'.repeat(64)},{...report,rules_sha256:'0'.repeat(64)},{...report,rule_count:129},{...report,matched_rule_count:2},{...report,limited:true},{...report,matches:[]},{...report,reason:'multiple_products'},{...report,matches:[{...report.matches[0],rule_id:'app_other'}]},{...report,matches:[{...report.matches[0],revision:2}]},{...report,matches:[{...report.matches[0],product_id:'other'}]},{...report,matches:[{...report.matches[0],evidence:[]}]},{...report,matches:[{...report.matches[0],evidence:[{field:'tls.body',op:'eq',pattern:'plaintext'}]}]}])expect(await validTestResult(value,o,d)).toBe(false)
  const unknown=await result(o,undefined,'unknown');expect(await validTestResult(unknown,o)).toBe(true);expect(await validTestResult({...unknown,matched_rule_count:1},o)).toBe(false)
  const conflict={...report,status:'conflict',reason:'multiple_products',rule_count:2,matched_rule_count:2,matches:[report.matches[0]!,{...report.matches[0]!,rule_id:'app_other',product_id:'other'}]};expect(await validTestResult(conflict,o)).toBe(true);expect(await validTestResult({...conflict,matches:[report.matches[0],report.matches[0]]},o)).toBe(false)
  expect(await validTestResult({...report,status:'unknown'},o)).toBe(false)
 })
})

describe('应用规则目录、保存与未知提交',()=>{
 it('有界分页与筛选，旧响应和账号切换不覆盖当前目录',async()=>{
  const owned=await record(),items=Array.from({length:20},(_,i)=>({...owned,id:'app_'+String(i).padStart(2,'0')}));request.mockResolvedValue({items,next_cursor:items.at(-1)!.id});const {state,wrapper}=host(useApplicationRules);await vi.waitFor(()=>expect(state.page.value.items).toHaveLength(20))
  expect(state.page.value.items).toHaveLength(20);state.next();await flushPromises();expect(state.error.value).toContain('完整');state.previous();await flushPromises();expect(state.cursors.value).toEqual([''])
  request.mockResolvedValue({items:[],next_cursor:''});state.search('  业务  ','false');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('active=false');expect(request.mock.lastCall?.[0]).toContain('keyword=')
  const old=deferred<unknown>();request.mockReturnValueOnce(old.promise);const reading=state.refresh(),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.search('其他','');await flushPromises();expect(signal.aborted).toBe(true);old.resolve({items:[owned],next_cursor:''});await reading;expect(state.page.value.items).toEqual([])
  user.value={...principal,tenant_id:'other'};await flushPromises();expect(state.cursors.value).toEqual(['']);expect(state.page.value.items).toEqual([])
  const waiting=deferred<unknown>();request.mockReturnValue(waiting.promise);const late=state.refresh();wrapper.unmount();waiting.resolve({items:[owned],next_cursor:''});await late;await state.refresh();expect(state.page.value.items).toEqual([])
 })
 it('损坏目录和连接失败不作为空成功，重复分页不前进',async()=>{
  request.mockResolvedValue({});const {state}=host(useApplicationRules);await flushPromises();expect(state.error.value).toContain('完整');state.next();state.previous();expect(state.cursors.value).toEqual([''])
  request.mockRejectedValueOnce('offline');await state.refresh();expect(state.error.value).toBe('应用规则读取失败。')
 })
 it('保存未知结果锁定相同输入和请求键，核对原提交后完成',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const {state}=host(useApplicationRules);await flushPromises();const owned=await record()
  request.mockRejectedValueOnce(new Error('连接中断'));expect(await state.save(input())).toBeUndefined();expect(state.unconfirmed.value).toBe(true);expect(state.draft()?.id).toBe('app_files');const first=request.mock.lastCall?.[1]
  state.clearError();expect(state.mutationError.value).toBe('连接中断');expect(await state.save({...input(),name:'其他'})).toBeUndefined();expect(state.mutationError.value).toContain('原提交')
  request.mockResolvedValueOnce({...owned,revision:99});expect(await state.confirm()).toBeUndefined();expect(state.unconfirmed.value).toBe(true)
  request.mockResolvedValueOnce(owned);expect(await state.confirm()).toEqual(owned);expect(request.mock.lastCall?.[1].headers).toEqual(first.headers);expect(request.mock.lastCall?.[1].body).toEqual(first.body);expect(state.unconfirmed.value).toBe(false);expect(state.draft()).toBeUndefined();expect(await state.confirm()).toBeUndefined()
  state.clearError();expect(state.mutationError.value).toBe('');expect(await state.save({...input(),name:' '})).toBeUndefined();expect(state.mutationError.value).toContain('名称')
 })
 it('明确冲突保留可编辑状态，超时与卸载保留未确认边界',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const {state,wrapper}=host(useApplicationRules);await flushPromises()
  request.mockRejectedValueOnce(new ApiError(409,'conflict','修订已变化'));expect(await state.save(input())).toBeUndefined();expect(state.unconfirmed.value).toBe(false)
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);vi.useFakeTimers();const saving=state.save(input());expect(await state.save(input())).toBeUndefined();await vi.advanceTimersByTimeAsync(30001);waiting.resolve(await record());await saving;expect(state.unconfirmed.value).toBe(true);expect(state.mutationError.value).toContain('确认');vi.useRealTimers()
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);const confirming=state.confirm();const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(await record());await confirming;expect(await state.save(input())).toBeUndefined()
 })
})

describe('应用规则表单与验证交互',()=>{
 it('合成原型使用独立材料适配器，不访问工程接口，仍须核对回执',async()=>{
  const preview=vi.fn().mockImplementation(async(_path:string,options:{body:{observation:AppObservation}})=>result(options.body.observation,undefined,'unknown'))
  const w=ui(ApplicationRuleTest,{api:{request:preview}});await finish(w);await vi.waitFor(()=>expect(body().text()).toContain('未知 · 0 条规则命中'))
  expect(preview.mock.lastCall?.[0]).toBe('/application-rules/test');expect(request).not.toHaveBeenCalled()
  preview.mockResolvedValueOnce({});await finish(w);await vi.waitFor(()=>expect(body().text()).toContain('回执与材料或规则快照不一致'));expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(false)
 })
 it('真实表单校验、组合条件和保存数据保持独立修订',async()=>{
  const w=ui(ApplicationRuleForm,{record:null,busy:false,unconfirmed:false,error:''});await finish(w);expect(body().text()).toContain('规则名称')
  await body().find('#app-rule-name').setValue(' 业务应用规则 ');await body().find('#app-rule-product-id').setValue('owned');await body().find('#app-rule-product-name').setValue('业务应用');await body().find('input[aria-label="候选域名条件 1 匹配值"]').setValue('files.example');await finish(w)
  expect(w.emitted('save')?.[0]?.[0]).toMatchObject({expected_revision:0,name:'业务应用规则',definition:{product_id:'owned',any:[{field:'http.host',op:'domain_suffix',value:'files.example'}]}})
  const all=body().find('section[aria-label="同时满足条件"]');await click(all as unknown as VueWrapper,'添加条件');await flushPromises();expect(body().findAll('.application-condition-row')).toHaveLength(2)
  const firstSelect=w.findAllComponents(Select).filter(c=>c.props('value')==='http.host').at(-1);firstSelect?.vm.$emit('update:value','http.path');await flushPromises();await body().find('input[aria-label="同时满足条件 1 匹配值"]').setValue('/documents');await finish(w);expect((w.emitted('save')?.at(-1)?.[0] as AppChange).definition.all).toEqual([{field:'http.path',op:'eq',value:'/documents'}])
  await body().find('button[aria-label="删除同时满足条件 1"]').trigger('click');await flushPromises();expect(body().findAll('.application-condition-row')).toHaveLength(1)
  await click(w,'关闭');expect(w.emitted('close')).toHaveLength(1)
 })
 it('没有变更和未知提交不可另行保存，错误反馈可见',async()=>{
  const owned=await record(),w=ui(ApplicationRuleForm,{record:owned,busy:false,unconfirmed:false,error:''});await finish(w);expect(w.emitted('save')).toBeUndefined();expect(body().text()).toContain('没有可提交')
  await w.setProps({unconfirmed:true,error:'服务响应未确认',draft:input()});await flushPromises();await click(w,'核对原提交');expect(w.emitted('confirm')).toHaveLength(1);expect(body().text()).toContain('字段已锁定');expect(body().text()).toContain('服务响应未确认');await finish(w);expect(w.emitted('save')).toBeUndefined()
 })
 it('验证实际输入摘要，修改材料清除旧结论，关闭取消请求',async()=>{
  request.mockImplementation(async(_path:string,options:{body:{observation:AppObservation}})=>result(options.body.observation));const w=ui(ApplicationRuleTest);await body().find('#application-test-name').setValue('files.example');await finish(w);await vi.waitFor(()=>expect(body().text()).toContain('规则候选'));expect(body().text()).toContain('验证材料 SHA-256')
  await body().find('#application-test-name').setValue('files.example.attacker.example');expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(false)
  const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);await finish(w);const signal=request.mock.lastCall?.[1].signal as AbortSignal;await click(w,'关闭');expect(signal.aborted).toBe(true);waiting.resolve(await result({...emptyObservation(),http_host:'files.example'}));await flushPromises();expect(w.emitted('close')).toHaveLength(1);expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(false)
 })
 it('所选定义副本、DNS 和 TLS 材料保留来源与缺测，异常不保留成功结论',async()=>{
  const d=definition();request.mockImplementation(async(_path:string,options:{body:{observation:AppObservation}})=>result(options.body.observation,d));const w=ui(ApplicationRuleTest,{definition:d,name:'业务文件服务',revision:2});await body().find('#application-test-name').setValue('files.example');await finish(w);await vi.waitFor(()=>expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(true));expect(request.mock.lastCall?.[0]).toBe('/application-rules/preview');expect(body().text()).toContain('修订 2 定义副本')
  w.findComponent(Select).vm.$emit('update:value','tls');await flushPromises();await body().find('#application-test-name').setValue('files.example');await body().find('#application-test-alpn').setValue('h2, http/1.1');await finish(w);await vi.waitFor(()=>expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(true));expect(request.mock.lastCall?.[1].body.observation.tls_alpn).toEqual(['h2','http/1.1'])
  request.mockResolvedValueOnce({});await finish(w);await vi.waitFor(()=>expect(body().text()).toContain('回执'));expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(false)
  request.mockRejectedValueOnce('offline');await finish(w);expect(body().text()).toContain('规则验证失败')
  await w.setProps({definition:undefined});w.findComponent(Select).vm.$emit('update:value','dns');await flushPromises();await body().find('#application-test-dns').setValue(new Array(33).fill('files.example').join('\n'));await finish(w);expect(body().text()).toContain('最多 32 个 DNS')
  await body().find('#application-test-dns').setValue('files.example\n api.files.example');request.mockImplementation(async(_p:string,options:{body:{observation:AppObservation}})=>result(options.body.observation,undefined,'unknown'));await finish(w);await settled();expect(request.mock.lastCall?.[1].body.observation.dns_names).toEqual(['files.example','api.files.example']);expect(body().text()).toContain('未知')
  user.value={...principal,role:'viewer'};await flushPromises();expect(w.emitted('close')).toHaveLength(1)
 })
 it('超时与卸载不显示迟到结果，验证期限没有被缩短',async()=>{
  const waiting=deferred<unknown>();request.mockReturnValue(waiting.promise);const w=ui(ApplicationRuleTest);vi.useFakeTimers();await finish(w);const signal=request.mock.lastCall?.[1].signal as AbortSignal;await vi.advanceTimersByTimeAsync(30001);expect(signal.aborted).toBe(true);waiting.resolve(await result(emptyObservation()));await flushPromises();expect(body().text()).toContain('未完成');expect(body().find('[aria-label="应用规则验证结果"]').exists()).toBe(false);vi.useRealTimers();w.unmount()
 })
})

describe('应用规则工作区',()=>{
 it('筛选无结果与初始空目录区分，尚未提交的输入不改变结果说明',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const w=ui(ApplicationRulesWorkspace);await flushPromises();expect(body().text()).toContain('暂无应用识别规则。管理员')
  const keyword=w.find('[aria-label="应用识别规则名称"]');await keyword.setValue('missing');expect(body().text()).toContain('暂无应用识别规则。管理员');await click(w,'检索');await flushPromises();expect(body().text()).toContain('没有符合筛选条件的应用识别规则');expect(request.mock.lastCall?.[0]).toContain('keyword=missing')
  await keyword.setValue('');await flushPromises();expect(body().text()).toContain('没有符合筛选条件');await click(w,'检索');await flushPromises();expect(body().text()).toContain('暂无应用识别规则。管理员')
  const state=w.findAllComponents(Select).find(s=>s.attributes('aria-label')==='应用识别规则状态');expect(state).toBeDefined();await state!.vm.$emit('update:value','true');await click(w,'检索');await flushPromises();expect(body().text()).toContain('没有符合筛选条件');expect(request.mock.lastCall?.[0]).toContain('active=true')
 })
 it('空状态、单表列表、修订详情与输入验证互斥展示',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const w=ui(ApplicationRulesWorkspace);await flushPromises();expect(body().text()).toContain('暂无应用识别规则');await click(w,'创建规则');expect(w.findComponent(ApplicationRuleForm).exists()).toBe(true);w.findComponent(ApplicationRuleForm).vm.$emit('close');await flushPromises()
  const owned=await record();request.mockResolvedValue({items:[owned],next_cursor:''});await click(w,'刷新');await vi.waitFor(()=>expect(body().findAll('table')).toHaveLength(1));expect(body().findAll('table')).toHaveLength(1);expect(body().text()).toContain('业务文件服务')
  request.mockResolvedValueOnce(owned);await click(w,'查看');await settled();expect(body().text()).toContain('定义 SHA-256');expect(request.mock.lastCall?.[0]).toContain('/revisions/1');expect(body().findAll('table')).toHaveLength(1)
  await body().find('#application-revision').setValue('');await flushPromises();expect(body().findAll('button').find(b=>b.text().replace(/\s/g,'')==='读取')?.attributes('disabled')).toBeDefined()
  await click(w,'关闭');await flushPromises();await click(w,'验证');expect(w.findComponent(ApplicationRuleTest).props('definition')).toEqual(owned.definition);w.findComponent(ApplicationRuleTest).vm.$emit('close');await flushPromises();await click(w,'编辑');expect(w.findComponent(ApplicationRuleForm).props('record')).toEqual(owned)
 })
 it('保存、原提交确认、检索与账号切换同步关闭对象视图',async()=>{
  request.mockResolvedValue({items:[],next_cursor:''});const w=ui(ApplicationRulesWorkspace);await flushPromises();await click(w,'创建规则');request.mockRejectedValueOnce(new Error('连接中断'));w.findComponent(ApplicationRuleForm).vm.$emit('save',input());await flushPromises();expect(body().text()).toContain('字段已锁定')
  request.mockResolvedValueOnce(await record()).mockResolvedValue({items:[],next_cursor:''});w.findComponent(ApplicationRuleForm).vm.$emit('confirm');await vi.waitFor(()=>expect(w.findComponent(ApplicationRuleForm).exists()).toBe(false))
  await click(w,'创建规则');request.mockResolvedValueOnce(await record()).mockResolvedValue({items:[],next_cursor:''});w.findComponent(ApplicationRuleForm).vm.$emit('save',input());await vi.waitFor(()=>expect(w.findComponent(ApplicationRuleForm).exists()).toBe(false))
  await click(w,'验证启用规则');expect(w.findComponent(ApplicationRuleTest).exists()).toBe(true);await body().find('form.application-rule-toolbar').trigger('submit');await flushPromises();expect(w.findComponent(ApplicationRuleTest).exists()).toBe(false)
  user.value={...principal,role:'viewer'};await flushPromises();expect(body().findAll('button').some(b=>b.text()==='创建规则')).toBe(false)
 })
 it('修订不一致或读取失败不展示旧定义，卸载取消详情读取',async()=>{
  const owned=await record();request.mockResolvedValue({items:[owned],next_cursor:''});const w=ui(ApplicationRulesWorkspace);await vi.waitFor(()=>expect(body().findAll('table')).toHaveLength(1));request.mockResolvedValueOnce({...owned,id:'app_other'});await click(w,'查看');await settled();expect(body().text()).toContain('所选对象');expect(body().find('.application-definition').exists()).toBe(false)
  request.mockRejectedValueOnce('offline');await click(w,'重试');await flushPromises();expect(body().text()).toContain('修订读取失败')
  await click(w,'关闭');const waiting=deferred<unknown>();request.mockReturnValueOnce(waiting.promise);await click(w,'查看');const signal=request.mock.lastCall?.[1].signal as AbortSignal;w.unmount();expect(signal.aborted).toBe(true);waiting.resolve(owned);await flushPromises()
 })
})
