import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {type ShallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message,Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal} from '../packages/shared/src/types'
import RulesWorkspace from '../platform/src/features/rules/RulesWorkspace.vue'
import RuleEditor from '../packages/shared/src/components/RuleEditor.vue'
import {session} from '../platform/src/session'
import {closedMessage,principal,rulePackage,sensor,task,rules,click,button,writeRule,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/rule-packages'?{items:[rulePackage]}:path==='/sensors'?{items:[sensor]}:rulePackage));vi.spyOn(message,'success').mockImplementation(closedMessage);vi.spyOn(message,'error').mockImplementation(closedMessage)})
async function workspace(path='/rules'){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/rules',component:RulesWorkspace}]});await router.push(path);await router.isReady();const wrapper=mount(RulesWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return{wrapper,router}}
async function name(value:string){const input=document.body.querySelector<HTMLInputElement>('#rule-package_name')!;input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('规则包编辑',()=>{
 it('切换历史视图后返回时保留未保存的名称和规则草稿',async()=>{
  const {wrapper,router}=await workspace();await click('创建规则包');await name('尚未保存的规则草稿');await writeRule(wrapper.getComponent(RuleEditor),rules)
  request.mockResolvedValue({items:[],next_cursor:''});await router.push('/rules?view=applications');await flushPromises();expect(document.body.querySelectorAll('[role=dialog]')).toHaveLength(0);expect(wrapper.text()).toContain('应用识别规则')
  await router.push('/rules');await flushPromises();expect(document.body.querySelectorAll('[role=dialog]')).toHaveLength(1);expect(document.body.querySelector<HTMLInputElement>('#rule-package_name')?.value).toBe('尚未保存的规则草稿');expect(document.body.textContent).not.toContain('创建应用识别规则')
  expect(wrapper.getComponent(RuleEditor).get('.cm-content').text()).toBe(rules)
 })
 it('跨规则工作区切换时只保留当前业务的弹窗',async()=>{
  const {router}=await workspace();await click('创建规则包');request.mockResolvedValue({items:[],next_cursor:''});await router.push('/rules?view=applications');await flushPromises();expect(document.body.querySelectorAll('[role=dialog]')).toHaveLength(0)
  await click('创建规则');expect(document.body.querySelectorAll('[role=dialog]')).toHaveLength(1);expect(document.body.textContent).toContain('创建应用识别规则');await router.push('/rules');await flushPromises();expect(document.body.querySelectorAll('[role=dialog]')).toHaveLength(1);expect(document.body.textContent).not.toContain('创建应用识别规则')
 })
 it('无数据与读取失败有恢复入口，字段摘要与修订正确显示',async()=>{
  request.mockResolvedValue({items:[]});const{wrapper}=await workspace();expect(wrapper.text()).toContain('暂无规则包');request.mockRejectedValueOnce('offline');await click('刷新');expect(wrapper.text()).toContain('规则包读取失败');request.mockResolvedValueOnce({items:[rulePackage]});await click('重试');expect(wrapper.text()).toContain(rulePackage.name);expect(wrapper.text()).toContain('4');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 it('编辑不可变修订，空文本与非法动作阻止保存，服务冲突保留草稿',async()=>{
  const{wrapper}=await workspace();await click('编辑规则');expect(document.body.textContent).toContain('修订 4');await name('');await click('保存修订');expect(document.body.textContent).toContain('请填写规则包名称')
  await name('HTTP 核对规则');const editor=wrapper.getComponent(RuleEditor);await writeRule(editor,'drop tcp any any -> any any (sid:9900001; rev:1;)');await click('保存修订');expect(document.body.textContent).toContain('第 1 行')
  await writeRule(editor,rules);request.mockRejectedValueOnce(new Error('修订冲突'));await click('保存修订');expect(document.body.textContent).toContain('修订冲突');expect(document.body.querySelector<HTMLInputElement>('#rule-package_name')?.value).toBe('HTTP 核对规则')
  request.mockResolvedValueOnce(rulePackage);await click('保存修订');expect(request.mock.calls.find(call=>call[1]?.method==='POST')?.[1].body).toMatchObject({id:rulePackage.id,expected_revision:4,name:'HTTP 核对规则',text:rules});expect(message.success).toHaveBeenCalled()
 })
 it('创建使用稳定标识，重复提交被阻止且离开页面不显示迟到成功',async()=>{
  const{wrapper}=await workspace();await click('创建规则包');await name('校验规则');await writeRule(wrapper.getComponent(RuleEditor),rules);request.mockRejectedValueOnce('offline');await click('保存修订');expect(document.body.textContent).toContain('保存失败');const id=request.mock.lastCall?.[1].body.id;expect(id).toMatch(/^pkg_[a-f0-9]{32}$/)
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);const action=button('保存修订');action.click();action.click();await flushPromises();expect(request.mock.lastCall?.[1].body.id).toBe(id);expect(request.mock.calls.filter(call=>call[1]?.method==='POST')).toHaveLength(2)
  const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve(rulePackage);await flushPromises();expect(message.success).not.toHaveBeenCalled()
 })
 it('只读账号可以查看高亮规则，编辑和重放入口不可用',async()=>{
  user.value={...principal,role:'viewer'};const{wrapper,router}=await workspace('/rules?view=samples');expect(wrapper.findAll('button').some(value=>value.text()==='创建规则包')).toBe(false);expect(wrapper.findAll('[role=tab]').map(tab=>tab.text())).toEqual(['规则包','应用识别规则']);expect(router.currentRoute.value.query.view).toBe('samples')
  await click('查看规则');expect(document.body.textContent).toContain('查看规则包');expect(document.body.querySelector('.cm-content')?.getAttribute('contenteditable')).toBe('false');expect(document.body.textContent).not.toContain('保存修订')
 })
 it('编辑读取失败显示原因，旧响应在离开后不打开弹窗',async()=>{
  const{wrapper}=await workspace();request.mockRejectedValueOnce(new Error('规则不可读取'));await click('编辑规则');expect(message.error).toHaveBeenCalledWith('规则不可读取')
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);await click('编辑规则');const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve(rulePackage);await flushPromises();expect(document.body.textContent).not.toContain('规则包修订')
 })
})

describe('原生规则装载检查',()=>{
 it('选定探针修订后提交，失败重试不更换幂等标识',async()=>{
  const{wrapper}=await workspace();await click('装载检查');const select=wrapper.getComponent(Select);expect(button('提交装载检查').disabled).toBe(true);await select.setValue(sensor.id,'value')
  request.mockRejectedValueOnce(new Error('检查连接超时'));await click('提交装载检查');expect(document.body.textContent).toContain('检查连接超时');const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];request.mockResolvedValueOnce({id:task.id});await click('提交装载检查');expect(request.mock.calls.filter(call=>call[0]===`/sensors/${sensor.id}/tasks`).map(call=>call[1].headers['Idempotency-Key'])).toEqual([key,key]);expect(document.body.textContent).toContain('检查任务已受理');expect(button('提交装载检查').disabled).toBe(true)
  await select.setValue('probe_2','value');select.vm.$emit('change','probe_2');await flushPromises();expect(button('提交装载检查').disabled).toBe(false);expect(document.body.textContent).not.toContain('检查任务已受理')
 })
 it('探针目录失败可重开，检查中取消请求不会显示迟到结果',async()=>{
  const{wrapper}=await workspace();request.mockRejectedValueOnce('offline');await click('装载检查');expect(document.body.textContent).toContain('探针读取失败');(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();await click('装载检查');await wrapper.getComponent(Select).setValue(sensor.id,'value')
  const pending=deferred<unknown>();request.mockImplementationOnce(()=>pending.promise);const action=button('提交装载检查');action.click();action.click();await flushPromises();expect(request.mock.calls.filter(call=>call[1]?.method==='POST')).toHaveLength(1);const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);pending.resolve({id:task.id});await flushPromises();expect(document.body.textContent).not.toContain('检查任务已受理')
 })
})

describe('规则编辑器',()=>{
 it('外部文本更新不回写，用户修改产生事件，权限和问题定位实时生效',async()=>{
  const wrapper=mount(RuleEditor,{props:{modelValue:rules},global:{plugins:[registerAnt]},attachTo:document.body});expect(wrapper.text()).toContain('基础检查通过');const editor=await writeRule(wrapper,rules+'\n# review');expect(wrapper.emitted('update:modelValue')?.[0]?.[0]).toContain('# review')
  await wrapper.setProps({modelValue:'invalid\n'.repeat(7)});expect(wrapper.emitted('update:modelValue')).toHaveLength(1);expect(wrapper.text()).toContain('基础检查问题');expect(wrapper.text()).toContain('其余问题');await wrapper.findAll('button')[0]!.trigger('click');expect(document.activeElement).toBe(editor.contentDOM)
  await wrapper.setProps({disabled:true});expect(editor.contentDOM.getAttribute('contenteditable')).toBe('false');await wrapper.setProps({disabled:false,readonly:true});expect(wrapper.find('.rule-editor-problems').exists()).toBe(false);await wrapper.setProps({readonly:false,modelValue:'# comment\n'+rules});expect(editor.contentDOM.getAttribute('contenteditable')).toBe('true');expect(wrapper.text()).toContain('2 行');wrapper.unmount();expect(editor.dom.isConnected).toBe(false)
 })
})
