import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {message,Select,InputNumber} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import MCPWorkspace from '../platform/src/features/mcp/MCPWorkspace.vue'
import BindingForm from '../platform/src/features/mcp/BindingForm.vue'
import ModelsView from '../platform/src/views/ModelsView.vue'
import {useMCP} from '../platform/src/features/mcp/useMCP'
import {bindingState,type Binding,type MCPInfo} from '../platform/src/features/mcp/mcp'
import {click,closedMessage,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
const global={plugins:[registerAnt]}
const info:MCPInfo={enabled:true,resource:'https://soc.example/mcp',issuer:'https://issuer.example',metadata_url:'https://soc.example/.well-known/oauth-protected-resource/mcp',protocol_versions:['2026-07-28','2025-11-25'],tools:[{name:'alerts.search',title:'告警检索',scope:'alerts:read',description:'仅返回当前租户有界元数据。'}]}
const binding:Binding={id:'mcp_1',name:'调查助手',issuer:info.issuer,subject:'subject_1',oauth_client_id:'agent_1',scopes:['alerts:read'],enabled:true,expires_at:'2090-01-01T00:00:00Z',requests_per_minute:60,owner_id:'user_1',revision:1,created_at:'2026-10-03T00:00:00Z',updated_at:'2026-10-03T00:00:00Z'}
beforeEach(()=>{request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?info:path==='/mcp/bindings'?{items:[binding]}:{items:[],available:true}));vi.spyOn(message,'success').mockImplementation(closedMessage)})
describe('MCP 服务接入界面',()=>{
  it('展示接入地址、单一身份列表和独立工具目录',async()=>{
    const wrapper=mount(MCPWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain(info.resource);expect(wrapper.text()).toContain('调查助手');expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('工具目录');expect(document.body.textContent).toContain('alerts.search');expect(wrapper.findAll('.ant-table')).toHaveLength(1);(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(document.body.textContent).not.toContain('仅返回当前租户有界元数据。')
    await click('配置');expect(document.body.textContent).toContain('登记后不能改绑');expect((document.querySelector('#subject') as HTMLInputElement|null)?.disabled??true).toBe(true);(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(document.body.textContent).not.toContain('登记后不能改绑')
  })
  it('未配置授权方的空状态关闭登记操作，读取失败支持重试',async()=>{
    request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?{...info,enabled:false}:{items:[]}));const wrapper=mount(MCPWorkspace,{global,attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('MCP 服务尚未启用');expect(wrapper.text()).toContain('暂无服务身份');expect(wrapper.findAll('.ant-table')).toHaveLength(0);expect([...document.querySelectorAll('button')].find(b=>b.textContent?.includes('登记服务身份'))?.disabled).toBe(true)
    request.mockRejectedValueOnce(new Error('存储读取受阻'));await click('刷新');expect(wrapper.text()).toContain('存储读取受阻');await click('重试');expect(wrapper.text()).not.toContain('存储读取受阻')
  })
  it('保存失败保留弹窗，成功后刷新，并且预算与权限结构不丢失',async()=>{
    const wrapper=mount(MCPWorkspace,{global,attachTo:document.body});await flushPromises();await click('配置');const form=wrapper.findComponent(BindingForm);request.mockRejectedValueOnce(new Error('修订已发生变化'));form.vm.$emit('save',{id:binding.id,expected_revision:1,name:binding.name,subject:binding.subject,oauth_client_id:binding.oauth_client_id,scopes:binding.scopes,enabled:false,expires_at:binding.expires_at,requests_per_minute:60});await flushPromises();expect(document.body.textContent).toContain('修订已发生变化')
    request.mockResolvedValueOnce({...binding,enabled:false,revision:2});form.vm.$emit('save',{id:binding.id,expected_revision:1,name:binding.name,subject:binding.subject,oauth_client_id:binding.oauth_client_id,scopes:binding.scopes,enabled:false,expires_at:binding.expires_at,requests_per_minute:60});await flushPromises();expect(wrapper.findComponent(BindingForm).exists()).toBe(false);expect(message.success).toHaveBeenCalledWith('服务身份配置已保存');expect(request.mock.calls.find(c=>c[1]?.method==='POST')?.[1].body.enabled).toBe(false)
  })
  it('页签遵循 History 查询参数，切换功能不会展示双表',async()=>{
    const router=createRouter({history:createMemoryHistory(),routes:[{path:'/models',component:ModelsView}]});await router.push('/models?view=mcp');await router.isReady();const wrapper=mount(ModelsView,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();expect(wrapper.findComponent(MCPWorkspace).exists()).toBe(true);await wrapper.findAll('[role=tab]').find(tab=>tab.text()==='模型提供方')!.trigger('click');await flushPromises();expect(router.currentRoute.value.query.view).toBeUndefined();expect(wrapper.findComponent(MCPWorkspace).exists()).toBe(false);await wrapper.findAll('[role=tab]').find(tab=>tab.text()==='MCP 服务')!.trigger('click');await flushPromises();expect(router.currentRoute.value.query.view).toBe('mcp');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  })
  it('到期、停用和无效有效期分别展示，不把无效日期当作启用',()=>{
    expect(bindingState(binding,0)).toBe('启用');expect(bindingState({...binding,expires_at:'2020-01-01T00:00:00Z'})).toBe('已到期');expect(bindingState({...binding,enabled:false})).toBe('停用');expect(bindingState({...binding,expires_at:'invalid'})).toBe('有效期异常')
  })
  it('删除按当前修订提交，失败保留身份记录和可重试入口',async()=>{
    mount(MCPWorkspace,{global,attachTo:document.body});await flushPromises();request.mockRejectedValueOnce(new Error('身份修订冲突'));await click('删除');await click('删除身份');expect(document.body.textContent).toContain('身份修订冲突');expect(request.mock.lastCall?.[1]).toMatchObject({method:'DELETE',body:{expected_revision:1}});request.mockResolvedValueOnce({ok:true});await click('删除');await click('删除身份');expect(message.success).toHaveBeenCalledWith('服务身份已删除')
  })
})
describe('MCP 身份表单',()=>{
  async function submit(_wrapper:ReturnType<typeof mount>){document.querySelector('form')!.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));await flushPromises()}
  async function fill(_wrapper:ReturnType<typeof mount>,selector:string,value:string){await flushPromises();const input=document.querySelector<HTMLInputElement>('input[id$="'+selector.slice(1)+'"]');expect(input).not.toBeNull();input!.value=value;input!.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
  it('新登记默认只读权限、180 天有效期与有限预算',async()=>{
    const before=Date.now();const wrapper=mount(BindingForm,{props:{record:null,issuer:info.issuer,pending:false,error:''},global,attachTo:document.body});await fill(wrapper,'#name','新助手');await fill(wrapper,'#subject','sub_2');await fill(wrapper,'#client','app_2');await submit(wrapper);const saved=wrapper.emitted('save')?.[0]?.[0] as Record<string,unknown>;expect(saved.scopes).toEqual(['alerts:read']);expect(saved.requests_per_minute).toBe(60);expect(saved.expected_revision).toBe(0);expect(Date.parse(saved.expires_at as string)-before).toBeGreaterThanOrEqual(180*86400000);expect(saved.id).toMatch(/^mcp_/)
  })
  it('协议流量权限独立授权，现有告警身份不自动取得协议权限',async()=>{
    const wrapper=mount(BindingForm,{props:{record:{...binding,expires_at:new Date(Date.now()+86400000).toISOString()},issuer:info.issuer,pending:false,error:''},global,attachTo:document.body});await flushPromises()
    const select=wrapper.getComponent(Select);expect(select.props('value')).toEqual(['alerts:read']);expect(select.props('options')).toContainEqual({value:'traffic:read',label:'协议流量检索'})
    await select.setValue(['traffic:read'],'value');await submit(wrapper);expect((wrapper.emitted('save')?.[0]?.[0] as Record<string,unknown>).scopes).toEqual(['traffic:read'])
  })
  it('校验空白身份、时区、到期及上限，并保留后端错误',async()=>{
    const valid={...binding,expires_at:new Date(Date.now()+180*86400000).toISOString()};const wrapper=mount(BindingForm,{props:{record:valid,issuer:info.issuer,pending:false,error:''},global,attachTo:document.body});await fill(wrapper,'#name',' ');await submit(wrapper);expect(document.body.textContent).toContain('请填写名称');await fill(wrapper,'#name','调查助手');await fill(wrapper,'#expires','2027-01-01T00:00:00');await submit(wrapper);expect(document.body.textContent).toContain('包含时区');await fill(wrapper,'#expires','2000-01-01T00:00:00Z');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined();await fill(wrapper,'#expires','2090-01-01T00:00:00Z');await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined();await fill(wrapper,'#expires',valid.expires_at);await submit(wrapper);expect(wrapper.emitted('save')).toHaveLength(1);await wrapper.setProps({error:'权限修订冲突'});expect(document.body.textContent).toContain('权限修订冲突');await click('取消');expect(wrapper.emitted('close')).toHaveLength(1)
  })
  it('提交期间禁用取消、关闭与重复提交',async()=>{
    const wrapper=mount(BindingForm,{props:{record:{...binding,expires_at:new Date(Date.now()+86400000).toISOString()},issuer:info.issuer,pending:true,error:''},global,attachTo:document.body});await submit(wrapper);expect(wrapper.emitted('save')).toBeUndefined();expect(document.querySelector('.ant-modal-close')).toBeNull();expect([...document.querySelectorAll('button')].find(b=>b.textContent?.replaceAll(' ','')==='取消')?.disabled).toBe(true)
  })
  it('没有权限范围或缺失调用预算时不能提交',async()=>{
    const wrapper=mount(BindingForm,{props:{record:{...binding,expires_at:new Date(Date.now()+86400000).toISOString()},issuer:info.issuer,pending:false,error:''},global,attachTo:document.body});await flushPromises();await wrapper.findComponent(Select).setValue([],'value');await submit(wrapper);expect(document.body.textContent).toContain('至少选择一个');await wrapper.findComponent(Select).setValue(['assets:read'],'value');await wrapper.findComponent(InputNumber).setValue(null,'value');await submit(wrapper);expect(document.body.textContent).toContain('1–120');expect(wrapper.emitted('save')).toBeUndefined()
  })
})
describe('MCP 请求生命周期',()=>{
  function setup(){let state!:ReturnType<typeof useMCP>;const component=defineComponent({setup(){state=useMCP();return()=>null}});const wrapper=mount(component);return{wrapper,state}}
  it('离开后取消读取和写入，不发布迟到结果',async()=>{
    const first=deferred<MCPInfo>();request.mockImplementationOnce(()=>first.promise);const{wrapper,state}=setup();const signal=request.mock.calls[0]?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);first.resolve(info);await flushPromises();expect(state.info.value).toBeNull();expect(await state.save({} as never)).toBeUndefined()
    const current=setup();await flushPromises();const mutation=deferred<Binding>();request.mockImplementationOnce(()=>mutation.promise);const promise=current.state.save({} as never);const writeSignal=request.mock.lastCall?.[1].signal as AbortSignal;expect(await current.state.save({} as never)).toBeUndefined();current.wrapper.unmount();expect(writeSignal.aborted).toBe(true);mutation.resolve(binding);expect(await promise).toBeUndefined()
  })
  it('未知错误有正式提示，停用服务禁止写入，清理操作错误可重新配置',async()=>{
    request.mockRejectedValue('offline');const{wrapper,state}=setup();await flushPromises();expect(state.error.value).toBe('MCP 服务读取失败');request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?{...info,enabled:false}:{items:[]}));state.refresh();await flushPromises();expect(await state.save({} as never)).toBeUndefined();request.mockImplementation((path:string)=>Promise.resolve(path==='/mcp'?info:{items:[binding]}));state.refresh();await flushPromises();request.mockRejectedValueOnce('offline');expect(await state.save({} as never)).toBeUndefined();expect(state.actionError.value).toBe('MCP 服务身份保存失败');state.clearActionError();expect(state.actionError.value).toBe('');wrapper.unmount()
  })
})
