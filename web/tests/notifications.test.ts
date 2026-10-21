import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,shallowRef} from 'vue'
import {createMemoryHistory,createRouter} from 'vue-router'
import {Checkbox,Select,message} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import {useNotifications} from '../platform/src/features/notifications/useNotifications'
import {channelNames,deliveryClass,type Channel,type ChannelChange,type Delivery} from '../platform/src/features/notifications/notifications'
import NotificationsWorkspace from '../platform/src/features/notifications/NotificationsWorkspace.vue'
import ChannelForm from '../platform/src/features/notifications/ChannelForm.vue'
import ChannelTable from '../platform/src/features/notifications/ChannelTable.vue'
import DeliveryTable from '../platform/src/features/notifications/DeliveryTable.vue'
import DeliveryDetail from '../platform/src/features/notifications/DeliveryDetail.vue'
import {click,button,closedMessage,deferred} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
const global={plugins:[registerAnt]}
const channel:Channel={id:'channel_owned',revision:3,name:'办公区通知',kind:'webhook',enabled:true,severities:['high','medium'],target:'https://example.invalid',has_secret:true,muted_until:null,updated_at:'2026-10-02T00:00:00Z'}
const delivery:Delivery={id:'delivery_owned',channel_id:channel.id,channel_name:channel.name,kind:'webhook',channel_revision:3,recipient:'',state:'uncertain',version:4,attempts:1,alert_count:2,receipt:{code:'acknowledgment_lost',http_status:200,provider_code:0,duration_ms:125},created_at:channel.updated_at,updated_at:channel.updated_at}
beforeEach(()=>{request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path==='/notifications/channels'?{items:[channel],available:true,development:false}:{items:[delivery],next_cursor:'cursor_owned'}));vi.spyOn(message,'success').mockImplementation(closedMessage)})
function host(view=shallowRef('channels')){let state!:ReturnType<typeof useNotifications>;const wrapper=mount(defineComponent({setup(){state=useNotifications(view);return()=>h('div')}}));return{state,view,wrapper}}
async function field(selector:string,value:string){const target=document.body.querySelector<HTMLInputElement|HTMLTextAreaElement>(selector);expect(target,selector).not.toBeNull();target!.value=value;target!.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}
async function workspace(path='/notifications'){const router=createRouter({history:createMemoryHistory(),routes:[{path:'/notifications',component:NotificationsWorkspace}]});await router.push(path);await router.isReady();const wrapper=mount(NotificationsWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();return{wrapper,router}}

describe('通知列表、请求与幂等操作',()=>{
 it('翻页使用服务端游标，查询和页签切换重置条件',async()=>{
  const{state,view}=host();state.next();await flushPromises();expect(state.channels.value).toEqual([channel]);expect(state.available.value).toBe(true);expect(state.development.value).toBe(false)
  view.value='deliveries';await flushPromises();state.next();await flushPromises();expect(request.mock.lastCall?.[0]).toContain('cursor=cursor_owned');state.previous();await flushPromises();state.previous();expect(state.cursors.value).toEqual(['']);state.search('failed');await flushPromises();expect(request.mock.lastCall?.[0]).toContain('state=failed');state.refresh();await flushPromises();expect(state.deliveries.value).toEqual([delivery]);view.value='channels';await flushPromises();expect(state.cursors.value).toEqual([''])
 })
 it('取消迟到查询，列表和操作异常提供明确提示',async()=>{
  const pending=deferred<unknown>();request.mockReturnValueOnce(pending.promise);const{state,wrapper}=host();const oldSignal=request.mock.lastCall?.[1].signal as AbortSignal;request.mockRejectedValueOnce(new Error('通知服务离线'));state.refresh();await flushPromises();expect(oldSignal.aborted).toBe(true);expect(state.error.value).toBe('通知服务离线');pending.resolve({items:[channel],available:true,development:true});await flushPromises();expect(state.channels.value).toEqual([])
  request.mockRejectedValueOnce('offline');state.refresh();await flushPromises();expect(state.error.value).toBe('通知数据读取失败');request.mockRejectedValueOnce('offline');expect(await state.save({} as ChannelChange)).toBe(false);expect(state.actionError.value).toBe('通知操作失败');state.clearActionError();expect(state.actionError.value).toBe('');const live=request.mock.calls.filter(call=>call[1]?.method!=='POST').at(-1)?.[1].signal as AbortSignal;wrapper.unmount();expect(live.aborted).toBe(true);expect(await state.retry(delivery)).toBe(false)
 })
 it('测试失败保留幂等键，确认受理后下次测试生成新的标识',async()=>{
  const{state}=host();await flushPromises();request.mockRejectedValueOnce(new Error('回执丢失'));expect(await state.test(channel)).toBe(false);const key=request.mock.lastCall?.[1].headers['Idempotency-Key'];request.mockResolvedValueOnce({state:'queued'});expect(await state.test(channel)).toBe(true);await flushPromises();const posts=request.mock.calls.filter(call=>call[1]?.method==='POST');expect(posts[1]?.[1].headers['Idempotency-Key']).toBe(key);request.mockResolvedValueOnce({state:'queued'});expect(await state.test(channel)).toBe(true);await flushPromises();expect(request.mock.calls.filter(call=>call[1]?.method==='POST').at(-1)?.[1].headers['Idempotency-Key']).not.toBe(key)
  request.mockResolvedValueOnce({state:'queued'});expect(await state.retry(delivery)).toBe(true);expect(request.mock.calls.filter(call=>call[1]?.method==='POST').at(-1)?.[1].body).toEqual({expected_version:4,acknowledge_duplicates:true})
 })
 it('阻止重复保存，切换页签和离开页面取消写入，不报告迟到成功',async()=>{
  const{state,view,wrapper}=host();await flushPromises();const mutation=deferred<unknown>();request.mockReturnValueOnce(mutation.promise);const first=state.save({} as ChannelChange);expect(await state.save({} as ChannelChange)).toBe(false);const signal=request.mock.lastCall?.[1].signal as AbortSignal;view.value='deliveries';await flushPromises();expect(signal.aborted).toBe(true);mutation.resolve({});expect(await first).toBe(false);expect(state.busy.value).toBe(false)
  const next=deferred<unknown>();request.mockReturnValueOnce(next.promise);const retry=state.retry(delivery);const second=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(second.aborted).toBe(true);next.reject(new Error('取消'));expect(await retry).toBe(false);expect(state.actionError.value).toBe('')
 })
})

describe('通知渠道表单和凭据处理',()=>{
 it('Escape 收起渠道下拉框并保留未提交的通知草稿',async()=>{
  const wrapper=mount(ChannelForm,{props:{record:null,pending:false,error:'',development:true},global,attachTo:document.body});await flushPromises();await field('input[id$="name"]','保留通知渠道草稿')
  for(const picker of wrapper.findAllComponents(Select)){
   await picker.find('.ant-select-selector').trigger('mousedown');await flushPromises();expect(picker.find('input').attributes('aria-expanded')).toBe('true')
   const escape=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(escape,'which',{value:27});picker.find('input').element.dispatchEvent(escape);await flushPromises()
   expect(wrapper.emitted('close')).toBeUndefined();expect(picker.find('input').attributes('aria-expanded')).toBe('false');expect(document.body.querySelector<HTMLInputElement>('input[id$="name"]')?.value).toBe('保留通知渠道草稿')
  }
  await click('取消');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('办公渠道须明确选择质量订阅，切换类型保留选择且不要求告警级别',async()=>{
  const wrapper=mount(ChannelForm,{props:{record:null,pending:false,error:'',development:true},global,attachTo:document.body});await flushPromises();await field('input[id$="name"]','检测质量通知');const picker=wrapper.findAllComponents(Select).find(item=>item.attributes('aria-label')==='订阅内容')!;expect(picker.props('value')).toEqual(['alerts']);expect(picker.props('options')?.map(item=>item.value)).toEqual(['alerts','quality']);await picker.setValue(['quality'],'value');await flushPromises();expect(document.body.textContent).not.toContain('告警级别');await wrapper.findAllComponents(Select)[0]!.setValue('wecom','value');await flushPromises();expect(picker.props('value')).toEqual(['quality']);await field('input[placeholder="https://example.com/webhook"]','https://example.invalid/notify');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({streams:['quality'],severities:[]});wrapper.unmount()
 })
 it('校验名称、地址和级别，保存失败保留草稿和稳定标识',async()=>{
  const wrapper=mount(ChannelForm,{props:{record:null,pending:false,error:'',development:false},global,attachTo:document.body});await flushPromises();await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('请输入渠道名称'));expect(wrapper.emitted('save')).toBeUndefined()
  await field('input[id$="name"]','告警通知');await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('请填写渠道目标地址'));await field('input[placeholder="https://example.com/webhook"]','https://example.invalid/hook');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));const change=wrapper.emitted('save')![0]![0] as ChannelChange;expect(change.id).toMatch(/^channel_[a-f0-9]{32}$/);expect(change.connection).toEqual({endpoint:'https://example.invalid/hook',secret:'',token:''})
  await wrapper.setProps({error:'修订冲突'});expect(document.body.textContent).toContain('修订冲突');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(2));expect((wrapper.emitted('save')![1]![0] as ChannelChange).id).toBe(change.id);await wrapper.setProps({pending:true});expect(button('取消').disabled).toBe(true);await wrapper.setProps({pending:false});await click('取消');expect(wrapper.emitted('close')).toHaveLength(1)
 })
 it('编辑不回显凭据，保留连接信息，静默时间非法时停止提交',async()=>{
  const wrapper=mount(ChannelForm,{props:{record:channel,pending:false,error:'',development:false},global,attachTo:document.body});await flushPromises();expect(document.body.querySelector('input[placeholder="https://example.com/webhook"]')).toBeNull();await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({id:channel.id,expected_revision:3});expect(wrapper.emitted('save')![0]![0]).not.toHaveProperty('connection')
  await field('input[placeholder^="留空表示不静默"]','bad-date');await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('静默截止时间无效'));await field('input[placeholder^="留空表示不静默"]','2026-10-03T18:00:00+08:00');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(2));expect(wrapper.emitted('save')![1]![0]).toMatchObject({muted_until:'2026-10-03T10:00:00.000Z'})
  await wrapper.findAllComponents(Checkbox)[0]!.setValue(true,'checked');await flushPromises();expect(document.body.querySelector('input[placeholder="https://example.com/webhook"]')).not.toBeNull()
 })
 it('邮件配置明确要求收件人，切换类型清除不相干的凭据',async()=>{
  const wrapper=mount(ChannelForm,{props:{record:null,pending:false,error:'',development:true},global,attachTo:document.body});await flushPromises();await field('input[id$="name"]','邮件通知');const kind=wrapper.findAllComponents(Select)[0]!;expect(kind.props('options')?.map(item=>item.value)).toContain('syslog_tcp');await kind.setValue('email','value');await flushPromises();await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('请填写 SMTP 主机'))
  await field('input[placeholder="smtp.example.com"]','smtp.example.invalid');await field('input[placeholder="security@example.com"]','security@example.invalid');await field('textarea','first@example.invalid; second@example.invalid\nthird@example.invalid');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({connection:{smtp_port:587,recipients:['first@example.invalid','second@example.invalid','third@example.invalid'],implicit_tls:false}})
  await kind.setValue('syslog_tls','value');await flushPromises();expect(document.body.textContent).toContain('字节计数');await field('input[placeholder="logs.example.com:6514"]','logs.example.invalid:6514');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(2));expect((wrapper.emitted('save')![1]![0] as ChannelChange).connection).toEqual({endpoint:'logs.example.invalid:6514'})
  await kind.setValue('feishu','value');await flushPromises();await field('input[placeholder="https://example.com/webhook"]','https://example.invalid/feishu');await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(3));expect((wrapper.emitted('save')![2]![0] as ChannelChange).connection).toEqual({endpoint:'https://example.invalid/feishu',secret:''})
 })
})

describe('审计日志渠道与回执',()=>{
 it('审计类别仅限 Syslog，办公渠道保留明确的质量订阅选项',async()=>{
  const auditChannel:Channel={...channel,kind:'syslog_tls',streams:['operations','logins'],severities:[]}
  const wrapper=mount(ChannelForm,{props:{record:auditChannel,pending:false,error:'',development:false},global,attachTo:document.body});await flushPromises()
  expect(document.body.textContent).toContain('订阅内容');expect(document.body.textContent).not.toContain('请选择告警级别')
  await click('保存渠道');await vi.waitFor(()=>expect(wrapper.emitted('save')).toHaveLength(1));expect(wrapper.emitted('save')![0]![0]).toMatchObject({streams:['operations','logins'],severities:[]});expect(wrapper.emitted('save')![0]![0]).not.toHaveProperty('connection')
  const streams=wrapper.findAllComponents(Select).find(item=>item.attributes('aria-label')==='订阅内容')!;await streams.setValue([],'value');await flushPromises();await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('请选择订阅内容'));expect(wrapper.emitted('save')).toHaveLength(1)
  await streams.setValue(['alerts','operations'],'value');await flushPromises();await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('请选择告警级别'));expect(wrapper.emitted('save')).toHaveLength(1);wrapper.unmount()
  const fresh=mount(ChannelForm,{props:{record:null,pending:false,error:'',development:true},global,attachTo:document.body});await flushPromises();await field('input[id$="name"]','日志转发');const kind=fresh.findAllComponents(Select)[0]!;await kind.setValue('syslog_tls','value');await flushPromises();const picker=fresh.findAllComponents(Select).find(item=>item.attributes('aria-label')==='订阅内容')!;await picker.setValue(['logins'],'value');await field('input[placeholder="logs.example.com:6514"]','logs.example.invalid:6514');await click('保存渠道');await vi.waitFor(()=>expect(fresh.emitted('save')).toHaveLength(1));expect(fresh.emitted('save')![0]![0]).toMatchObject({streams:['logins'],severities:[]});await kind.setValue('webhook','value');await flushPromises();expect(fresh.findAllComponents(Select).find(item=>item.attributes('aria-label')==='订阅内容')!.props('options')?.map(item=>item.value)).toEqual(['alerts','quality']);await field('input[placeholder="https://example.com/webhook"]','https://example.invalid/notify');await click('保存渠道');await vi.waitFor(()=>expect(fresh.emitted('save')).toHaveLength(2));expect(fresh.emitted('save')![1]![0]).toMatchObject({streams:['alerts']})
 })
 it('审计列表使用记录数并区分登录日志与安全告警',async()=>{
  const record:Delivery={...delivery,kind:'syslog_tls',stream:'logins',record_count:1,alert_count:0,receipt:{code:'storage_acknowledgment_unavailable',frames:1,frames_written:1}}
  const list=mount(DeliveryTable,{props:{items:[record]},global,attachTo:document.body});expect(list.text()).toContain('登录日志');expect(list.text()).toContain('记录数');list.unmount()
  const detail=mount(DeliveryDetail,{props:{record,busy:false},global,attachTo:document.body});expect(document.body.textContent).toContain('登录日志');expect(document.body.textContent).toContain('记录数量');detail.unmount()
  const channels=mount(ChannelTable,{props:{items:[{...channel,kind:'syslog_tls',streams:['operations','logins'],severities:[]}],busy:false,available:true},global,attachTo:document.body});expect(channels.text()).toContain('操作日志、登录日志');expect(channels.text()).toContain('不订阅告警')
 })
})

describe('渠道列表、推送回执与工作区交互',()=>{
 it('渠道配置和测试遵守可用状态，详情说明确认边界和重复风险',async()=>{
  const table=mount(ChannelTable,{props:{items:[channel],busy:false,available:true},global,attachTo:document.body});expect(table.text()).toContain(channelNames.webhook);await click('配置');expect(table.emitted('edit')?.[0]?.[0]).toEqual(channel);await click('测试');await click('发送测试');expect(table.emitted('test')?.[0]?.[0]).toEqual(channel);await table.setProps({available:false,items:[{...channel,enabled:false,severities:['future']}]});expect(button('配置').disabled).toBe(true);expect(table.text()).toContain('停用');expect(table.text()).toContain('future');table.unmount()
  const list=mount(DeliveryTable,{props:{items:[delivery]},global,attachTo:document.body});await click('查看');expect(list.emitted('view')?.[0]?.[0]).toEqual(delivery);expect(list.text()).toContain('渠道目标');list.unmount()
  const detail=mount(DeliveryDetail,{props:{record:delivery,busy:false},global,attachTo:document.body});expect(document.body.textContent).toContain('发送后连接中断');expect(document.body.textContent).toContain('125 ms');await click('人工重试');await click('确认重试');expect(detail.emitted('retry')?.[0]?.[0]).toEqual(delivery);await detail.setProps({record:{...delivery,state:'accepted',receipt:{code:'future'},recipient:'user@example.invalid'}});expect(document.body.textContent).toContain('其他处理状态');expect(document.body.textContent).toContain('未获取');expect(document.body.textContent).not.toContain('人工重试');await detail.setProps({record:{...delivery,receipt:{}}});expect(document.body.textContent).toContain('尚未获取渠道回执');(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(detail.emitted('close')).toHaveLength(1);await detail.setProps({record:null});expect(document.body.textContent).not.toContain(delivery.id)
  for(const state of ['accepted','transport_written','failed','uncertain','retry','queued'] as const)expect(deliveryClass(state)).toMatch(/^status-/)
 })
 it('Syslog 部分写入显示帧数和重复风险，缺测不补零',async()=>{
  const wrapper=mount(DeliveryDetail,{props:{record:{...delivery,kind:'syslog_tls',receipt:{code:'transport_result_unknown',frames:10,frames_written:3}},busy:false},global,attachTo:document.body});await flushPromises();expect(document.body.textContent).toContain('已完整写入 3 / 10 帧');expect(document.body.textContent).toContain('重试可能重复发送');expect(document.body.textContent).not.toContain('HTTP 状态')
  await wrapper.setProps({record:{...delivery,kind:'syslog_tls',receipt:{frames:10,frames_written:0}}});expect(document.body.textContent).toContain('已完整写入 0 / 10 帧');await wrapper.setProps({record:{...delivery,kind:'syslog_tcp',receipt:{}}});expect(document.body.textContent).toContain('未获取');expect(document.body.textContent).not.toContain('已完整写入 0 /')
 })
 it('渠道配置保存与测试受理后进入单表推送日志',async()=>{
  const{wrapper,router}=await workspace();expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('配置');await click('保存渠道');await vi.waitFor(()=>expect(message.success).toHaveBeenCalledWith('通知渠道已保存'));await click('测试');await click('发送测试');await vi.waitFor(()=>expect(router.currentRoute.value.query.view).toBe('deliveries'));expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 it('推送日志翻页、查询与重置沿用受控筛选',async()=>{
  const{wrapper}=await workspace('/notifications?view=deliveries');expect(wrapper.findAll('.ant-table')).toHaveLength(1);await click('下一页');expect(request.mock.lastCall?.[0]).toContain('cursor=cursor_owned');await click('上一页');await wrapper.get('form').trigger('submit');await flushPromises();await click('重置');expect(wrapper.findAll('.ant-table')).toHaveLength(1)
 })
 it('推送详情确认人工重试后可关闭回执',async()=>{
  const{wrapper}=await workspace('/notifications?view=deliveries');await click('查看');await click('人工重试');await click('确认重试');expect(message.success).toHaveBeenCalledWith('人工重试已受理');(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(wrapper.getComponent(DeliveryDetail).props('record')).toBeNull()
 })
 it('返回通知渠道并取消创建时不遗留凭据表单',async()=>{
  await workspace('/notifications?view=deliveries');await click('通知渠道');await click('创建渠道');await click('取消');expect(document.body.textContent).not.toContain('连接信息与凭据加密保存')
 })
 it('未启用、空列表、失败与冲突有明确状态，操作失败保留当前界面',async()=>{
  request.mockResolvedValueOnce({items:[],available:false,development:false});const{wrapper}=await workspace();expect(wrapper.text()).toContain('通知服务尚未启用');expect(button('创建渠道').disabled).toBe(true);expect(wrapper.text()).toContain('暂无通知渠道');request.mockRejectedValueOnce(new Error('渠道读取超时'));await click('刷新');expect(wrapper.text()).toContain('渠道读取超时');await click('重试');await click('配置');request.mockRejectedValueOnce(new Error('配置修订已变化'));await click('保存渠道');await vi.waitFor(()=>expect(document.body.textContent).toContain('配置修订已变化'));expect(document.body.querySelector<HTMLInputElement>('input[id$="name"]')?.value).toBe(channel.name);await click('取消');request.mockRejectedValueOnce(new Error('测试受理失败'));await click('测试');await click('发送测试');expect(wrapper.text()).toContain('测试受理失败');await click('推送日志');request.mockResolvedValueOnce({items:[],next_cursor:''});await click('刷新');expect(wrapper.text()).toContain('当前条件下没有推送日志')
 })
})
