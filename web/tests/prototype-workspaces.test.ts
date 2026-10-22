import {webcrypto} from 'node:crypto'
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest'
import {DOMWrapper,flushPromises,mount} from '@vue/test-utils'
import {createMemoryHistory,createRouter} from 'vue-router'
import Antd,{message} from 'ant-design-vue'
import {computed,defineComponent,h} from 'vue'
import type {WatchlistChange} from '../packages/shared/src/watchlists'
import WatchlistForm from '../packages/shared/src/components/WatchlistForm.vue'
import WatchlistsPreview from '../../prototype/src/components/WatchlistsPreview.vue'
import IncidentNotesPreview from '../../prototype/src/components/IncidentNotesPreview.vue'
import IncidentNoteForm from '../platform/src/features/incidents/IncidentNoteForm.vue'
import CollectorCapabilityPreview from '../../prototype/src/components/CollectorCapabilityPreview.vue'
import CollectorView from '../../prototype/src/views/CollectorView.vue'
import MCPAccessPreview from '../../prototype/src/components/MCPAccessPreview.vue'
import ResponseActionsPreview from '../../prototype/src/components/ResponseActionsPreview.vue'
import TaskTable from '../packages/shared/src/components/TaskTable.vue'
import {validResponseProtection} from '../packages/shared/src/responseProtection'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {watchlistExamples,previewWatchlistExample,watchlistExampleClock} from '../../prototype/src/data/watchlists'
import {collectorPrototypeScreens} from '../../prototype/src/data/collectorNavigation'
import {incidentRecord,incidentClosed} from './incidentFixtures'
import {button,click} from './fixtures'

const scope=()=>new DOMWrapper(document.body)
beforeEach(()=>{vi.stubGlobal('crypto',webcrypto);vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('合成原型不得发出网络请求')))})
// 静态消息有独立的挂载实例，须在每项真实 DOM 用例后释放。
afterEach(()=>message.destroy())
async function routing(path='/work?state=data'){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:{template:'<div />'}}]});await router.push(path);await router.isReady();return router
}
async function lists(query=''){
 const router=await routing('/work?state='+(query.includes('action')?'action':'data')+query.replace('&state=action',''))
 const state=computed(()=>router.currentRoute.value.query.state==='action'?'action':'data')
 const host=defineComponent(()=>()=>h(WatchlistsPreview,{state:state.value,onState:(value:string)=>{void router.replace({query:{...router.currentRoute.value.query,state:value}})}}))
 const wrapper=mount(host,{attachTo:document.body,global:{plugins:[Antd,router]}})
 await vi.waitFor(()=>expect(scope().text()).toContain('管理地址保护（示例）'));await flushPromises();return{wrapper,router}
}
const field=async(label:string,value:string)=>{const input=document.querySelector<HTMLInputElement|HTMLTextAreaElement>(`[aria-label="${label}"]`)!;input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));await flushPromises()}

describe('名单合成示例与工程契约',()=>{
 it('所有目录与有效、过期、停用示例经过生产记录校验，预览不授予执行资格',async()=>{
  const rows=await watchlistExamples();expect(rows).toHaveLength(4)
  const valid=rows[0]!,expired=rows[2]!,wide=rows[3]!
  const matching={sensor_id:'probe_hq_example',registration_id:'reg_hq_example',type:'ip' as const,value:'192.0.2.10'}
  const result=await previewWatchlistExample({definition:valid.definition,active:true,targets:[matching]})
  expect(result.matches[0]?.matched).toBe(true);expect(result.effective).toBe(true);expect(result.execution_authorized).toBe(false);expect(result.fact_deletion_allowed).toBe(false)
  expect(Date.parse(result.checked_at)).toBe(watchlistExampleClock)
  expect((await previewWatchlistExample({definition:expired.definition,active:true,targets:[]})).reasons).toContain('expired')
  expect((await previewWatchlistExample({definition:wide.definition,active:false,targets:[]})).reasons).toContain('scope_too_broad')
  expect(fetch).not.toHaveBeenCalled()
 })
 it('单一名单表与互斥详情，修订读取不增加第二个业务表',async()=>{
  await lists();expect(document.querySelectorAll('.ant-table')).toHaveLength(1)
  await click('查看');expect(document.querySelectorAll('.ant-modal')).toHaveLength(1);expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0)
  expect(scope().text()).toContain('合成名单示例');expect(fetch).not.toHaveBeenCalled()
 })
 it('创建表单默认停用，关闭返回列表且不提交任何外部请求',async()=>{
  const {wrapper}=await lists();await click('创建名单');expect(wrapper.findComponent(WatchlistForm).props('record')).toBeNull();expect(document.querySelectorAll('.ant-modal')).toHaveLength(1)
  await click('关闭');await flushPromises();expect(document.querySelectorAll('.ant-modal')).toHaveLength(0);expect(fetch).not.toHaveBeenCalled()
 })
 it('只按名单名称检索，匹配值和配置依据不扩大查询范围',async()=>{
  await lists();await field('筛选名单名称','192.0.2.10');await click('查询');expect(scope().text()).toContain('暂无名单')
  await field('筛选名单名称','管理地址');await click('查询');expect(document.querySelectorAll('.ant-table-row')).toHaveLength(1);expect(scope().text()).toContain('管理地址保护（示例）')
 })
 it('未知提交允许关闭，目录恢复同一冻结输入并核对原回执',async()=>{
  const {wrapper}=await lists('&state=action&list_state=unknown'),row=(await watchlistExamples())[0]!,input:WatchlistChange={id:row.id,expected_revision:row.revision,name:'待核对合成名称',description:row.description,active:false,definition:row.definition}
  wrapper.findComponent(WatchlistForm).vm.$emit('save',input);await flushPromises();await vi.waitFor(()=>expect(wrapper.findComponent(WatchlistForm).props('unconfirmed')).toBe(true))
  await click('关闭');expect(wrapper.findComponent(WatchlistForm).exists()).toBe(false);expect(scope().text()).toContain('原合成请求与输入已保留')
  await click('核对原提交');expect(wrapper.findComponent(WatchlistForm).props('draft')).toEqual(input);expect(wrapper.findComponent(WatchlistForm).props('unconfirmed')).toBe(true)
  await click('核对原提交',document.querySelector('.ant-modal-footer')!);await vi.waitFor(()=>expect(wrapper.findComponent(WatchlistForm).exists()).toBe(false));expect(scope().text()).toContain('待核对合成名称');expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['conflict','unknown'])('%s 保存路径保留原修订和冻结提交边界',async mode=>{
  const {wrapper}=await lists('&state=action&list_state='+mode),row=(await watchlistExamples())[0]!
  const input:WatchlistChange={id:row.id,expected_revision:row.revision,name:row.name,description:row.description,active:false,definition:row.definition}
  wrapper.findComponent(WatchlistForm).vm.$emit('save',input);await flushPromises()
  await vi.waitFor(()=>expect(scope().text()).toContain(mode==='conflict'?'合成修订冲突示例':'正在演示回执未知状态'))
  if(mode==='unknown'){expect(wrapper.findComponent(WatchlistForm).props('unconfirmed')).toBe(true);await click('核对原提交',document.querySelector('.ant-modal-footer')!);await vi.waitFor(()=>expect(wrapper.findComponent(WatchlistForm).exists()).toBe(false))}
  expect(fetch).not.toHaveBeenCalled()
 })
})

describe('调查笔记合成工作区',()=>{
 it('创建、详情和历史不堆叠业务表，输入按工程表单校验',async()=>{
  mount(IncidentNotesPreview,{props:{parent:incidentRecord},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(1)
  await click('建立笔记');await field('笔记标题','合成笔记 <script>示例</script>');await field('笔记正文','材料来自固定示例，需继续核对实际业务影响。');await click('保存笔记');await flushPromises();expect(scope().text()).toContain('合成笔记 <script>示例</script>');expect(document.querySelector('.ant-modal script')).toBeNull();expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['empty','loading','error'])('%s 读取状态清除内容且错误可重试',async scenario=>{
  mount(IncidentNotesPreview,{props:{parent:incidentRecord,scenario},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(0)
  if(scenario==='error'){await click('重试');expect(document.querySelectorAll('.ant-modal .ant-table')).toHaveLength(1)}
  if(scenario==='loading')expect(scope().text()).toContain('正在读取数据')
  expect(fetch).not.toHaveBeenCalled()
 })
 it('未知提交可关闭后重新打开，保留冻结材料并使用原输入核对',async()=>{
  const wrapper=mount(IncidentNotesPreview,{props:{parent:incidentRecord,scenario:'unknown',open:true},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();const before=(document.querySelector('[aria-label="笔记正文"]') as HTMLTextAreaElement).value
  await click('关闭');expect(wrapper.emitted('close')).toHaveLength(1);await wrapper.setProps({open:false});await wrapper.setProps({open:true});await flushPromises();expect((document.querySelector('[aria-label="笔记正文"]') as HTMLTextAreaElement).value).toBe(before)
  await click('核对原提交',document.querySelector('.ant-modal-footer')!);await flushPromises();expect(scope().text()).toContain('建立笔记');expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['核对原提交','建立笔记'])('未知提交返回列表后通过%s恢复同一笔记、修订、材料与原提交键',async recovery=>{
  const key=vi.spyOn(crypto,'randomUUID'),wrapper=mount(IncidentNotesPreview,{props:{parent:incidentRecord,scenario:'unknown'},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises()
  const original=structuredClone(wrapper.getComponent(IncidentNoteForm).props('draft'))!,noteID=wrapper.getComponent(IncidentNoteForm).props('record')!.id
  expect(key).toHaveBeenCalledTimes(1);expect(button('返回笔记').disabled).toBe(false)
  await click('返回笔记');expect(wrapper.findComponent(IncidentNoteForm).exists()).toBe(false);expect(scope().text()).toContain('上次笔记提交尚未确认');expect(button('建立笔记').disabled).toBe(false)
  await click(recovery);const restored=wrapper.getComponent(IncidentNoteForm)
  expect(restored.props('draft')).toEqual(original);expect(restored.props('record')?.id).toBe(noteID);expect(restored.props('editing')).toBe(true);expect(restored.props('unconfirmed')).toBe(true)
  expect((document.querySelector('[aria-label="笔记正文"]') as HTMLTextAreaElement).disabled).toBe(true)
  await click('核对原提交',document.querySelector('.ant-modal-footer')!);expect(wrapper.findComponent(IncidentNoteForm).exists()).toBe(false);expect(document.querySelectorAll('.ant-table-row')).toHaveLength(1)
  await click('查看');expect(document.querySelector('.ant-modal')?.textContent).toContain(noteID);expect(document.querySelector('.ant-modal')?.textContent).toContain('3 · 基于事件修订 '+incidentRecord.revision);expect(key).toHaveBeenCalledTimes(1);expect(fetch).not.toHaveBeenCalled()
 })
 it('未知提交允许使用 Escape 关闭，重新打开仍保留冻结材料',async()=>{
  const wrapper=mount(IncidentNotesPreview,{props:{parent:incidentRecord,scenario:'unknown',open:true},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();const original=structuredClone(wrapper.getComponent(IncidentNoteForm).props('draft'))
  const escape=new KeyboardEvent('keydown',{key:'Escape',keyCode:27,bubbles:true});Object.defineProperty(escape,'which',{value:27});document.querySelector('.ant-modal-wrap')!.dispatchEvent(escape);await flushPromises();expect(wrapper.emitted('close')).toHaveLength(1)
  await wrapper.setProps({open:false});await wrapper.setProps({open:true});await flushPromises();expect(wrapper.getComponent(IncidentNoteForm).props('draft')).toEqual(original);expect(wrapper.getComponent(IncidentNoteForm).props('unconfirmed')).toBe(true);expect(fetch).not.toHaveBeenCalled()
 })
 it('结案笔记详情使用实际字段名称并说明固化保留期限',async()=>{
  mount(IncidentNotesPreview,{props:{parent:incidentClosed,scenario:'detail'},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();const detail=document.querySelector('.ant-modal')!.textContent!
  for(const label of ['笔记标识','笔记状态','原始作者','建立时间','最近记录','修订','变更说明','当前修订保留期限','按固化期限保留'])expect(detail).toContain(label)
  expect(detail).not.toContain('活动事件的历史受保护');expect(detail).not.toContain('活动事件的笔记及历史受保护');expect(button('编辑笔记').disabled).toBe(true);expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['closed','foreign'])('%s 示例禁止非作者或已结案事件编辑',async scenario=>{
  mount(IncidentNotesPreview,{props:{parent:scenario==='closed'?incidentClosed:incidentRecord,scenario:scenario==='foreign'?'foreign':'data'},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();if(scenario==='closed')expect(button('建立笔记').disabled).toBe(true);await click('查看');expect(button('编辑笔记').disabled).toBe(true)
 })
 it('修订冲突不生成成功列表记录，错误原因可见',async()=>{
  mount(IncidentNotesPreview,{props:{parent:incidentRecord,scenario:'conflict'},attachTo:document.body,global:{plugins:[Antd]}});await flushPromises();await field('笔记变更说明','核对最新材料');await click('保存笔记');expect(scope().text()).toContain('合成修订冲突示例');expect(document.querySelectorAll('.ant-modal form')).toHaveLength(1);expect(fetch).not.toHaveBeenCalled()
 })
})

describe('采集器规范视图',()=>{
 it.each(['task=missing','task=','task','task=task_example_1&task=task_example_4'].flatMap(query=>['data','detail'].map(state=>({query,state:state as 'data'|'detail'}))))('$state 状态拒绝显式无效任务 $query，不回退到首条记录',async({query,state})=>{
  const router=await routing('/work?'+query),wrapper=mount(CollectorCapabilityPreview,{props:{view:'tasks',state},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
  expect(document.querySelector('.ant-modal')).not.toBeNull();const modal=new DOMWrapper(document.querySelector('.ant-modal')!)
  expect(modal.text()).toContain('任务不在当前合成示例范围内');expect(modal.text()).not.toContain('task_example_1');expect(modal.text()).not.toContain('task_example_4');expect(wrapper.getComponent(TaskTable).props('detail')?.item).toBeNull();expect(fetch).not.toHaveBeenCalled()
 })
 it.each([{query:'',id:'task_example_1'},{query:'&task=task_example_4',id:'task_example_4'}])('详情示例仅在未指定任务时使用默认记录，指定有效任务保持精确选择 $id',async({query,id})=>{
  const router=await routing('/work?state=detail'+query),wrapper=mount(CollectorCapabilityPreview,{props:{view:'tasks',state:'detail'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
  expect(document.querySelector('.ant-modal')?.textContent).toContain(id);expect(wrapper.getComponent(TaskTable).props('detail')?.item?.id).toBe(id);expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['task_example_4','missing'])('刷新详情重新核对指定合成任务 %s，提供可见反馈且不替换目标',async task=>{
  const router=await routing('/work?task='+task),wrapper=mount(CollectorCapabilityPreview,{props:{view:'tasks',state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises();await click('刷新详情',document.querySelector('.ant-modal')!)
  await vi.waitFor(()=>expect(document.querySelector('.ant-message-notice')?.textContent).toContain(task==='missing'?'指定任务不在当前合成示例范围内，未读取其他任务':'已重新读取合成任务 task_example_4'))
  expect(router.currentRoute.value.query.task).toBe(task);expect(wrapper.getComponent(TaskTable).props('detail')?.item?.id).toBe(task==='missing'?undefined:task);expect(document.querySelector('.ant-modal')?.textContent).not.toContain('task_example_1');expect(fetch).not.toHaveBeenCalled()
 })
 it('刷新期间切换到无效任务后清除原任务与刷新消息',async()=>{
  const router=await routing('/work?task=task_example_4'),wrapper=mount(CollectorCapabilityPreview,{props:{view:'tasks',state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
  button('刷新详情',document.querySelector('.ant-modal')!).click();await router.replace('/work?task=missing');await flushPromises();expect(wrapper.getComponent(TaskTable).props('detail')?.item).toBeNull();expect(document.querySelector('.ant-modal')?.textContent).toContain('任务不在当前合成示例范围内');expect(document.querySelector('.ant-message-notice')?.textContent??'').not.toContain('task_example_4');expect(fetch).not.toHaveBeenCalled()
 })
 it('通信身份说明固定合成快照的读取边界，不提供无执行能力的刷新按钮',async()=>{
  const router=await routing();mount(CollectorCapabilityPreview,{props:{view:'identity',state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
  expect(scope().text()).toContain('本页展示固定合成证书快照，不读取本机证书');expect(scope().text()).toContain('刷新证书状态请在实际采集器中操作');expect(Array.from(document.querySelectorAll('button')).some(item=>item.textContent==='刷新证书状态')).toBe(false);expect(fetch).not.toHaveBeenCalled()
 })
 it.each(['overview','interfaces','capture','identity','tasks'] as const)('%s 使用交付组件且所有观测保持合成隔离',async view=>{
  const router=await routing(),wrapper=mount(CollectorCapabilityPreview,{props:{view,state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises();expect(document.querySelectorAll('.ant-table').length).toBeLessThanOrEqual(1)
  if(view==='capture'){await click('保存采集目标');expect(scope().text()).toContain('实际采集尚未应用');expect(scope().text()).toContain('待应用')}
  if(view==='tasks'){await click('查看');expect(document.querySelectorAll('.ant-modal')).toHaveLength(1);expect(router.currentRoute.value.query.task).toBeTruthy()}
  expect(fetch).not.toHaveBeenCalled();wrapper.unmount()
 })
 it.each(collectorPrototypeScreens)('$path 对应的示例可加载，工作区不发真实请求',async screen=>{
  const router=await routing(screen.path),wrapper=mount(CollectorView,{attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
  expect(wrapper.find('h1').text()).toBe(screen.title);expect(scope().text()).toContain('采集器合成示例');expect(fetch).not.toHaveBeenCalled();wrapper.unmount()
 })
 it('规范9路由复用原工作区组件与同一页签，不提供未交付写动作',async()=>{
  const router=createRouter({history:createMemoryHistory(),routes:collectorPrototypeScreens.map(screen=>({path:screen.path,component:CollectorView,meta:{collectorPage:screen.page}}))});await router.push('/collector/network/interfaces?source=site-a#network');await router.isReady()
  const wrapper=mount(CollectorView,{attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises();expect(scope().text()).toContain('网卡列表');expect(scope().text()).not.toContain('配置管理网络');expect(document.querySelectorAll('.ant-table')).toHaveLength(1)
  const capture=Array.from(document.querySelectorAll<HTMLElement>('[role=tab]')).find(tab=>tab.textContent==='采集配置')!;capture.click();await flushPromises();expect(router.currentRoute.value.path).toBe('/collector/network/capture');expect(router.currentRoute.value.query.source).toBe('site-a');expect(router.currentRoute.value.hash).toBe('#network');expect(fetch).not.toHaveBeenCalled();wrapper.unmount()
 })
})

describe('MCP 接入说明',()=>{
 it('弹窗、页签与九项工具名称遵循实际服务端目录',async()=>{
  mount(MCPAccessPreview,{attachTo:document.body,global:{plugins:[Antd]}});await click('工具与资源')
  expect(document.querySelector('.ant-modal-title')?.textContent).toBe('MCP 工具与资源');expect(document.querySelector('.ant-modal [role="tab"][aria-selected="true"]')?.textContent).toBe('工具目录')
  expect(Array.from(document.querySelectorAll('.ant-modal .ant-table-row')).map(row=>Array.from(row.querySelectorAll('td')).map(cell=>cell.textContent))).toEqual([
   ['alerts.search','告警检索','alerts:read'],['alerts.aggregate','态势统计','alerts:read'],['assets.get','资产详情','assets:read'],['sensors.list','探针列表','sensors:read'],['alerts.fields','告警检索字段','alerts:read'],['alerts.filter.validate','告警表达式校验','alerts:read'],['traffic.search','协议流量检索','traffic:read'],['traffic.fields','协议检索字段','traffic:read'],['traffic.filter.validate','协议表达式校验','traffic:read']
  ]);expect(fetch).not.toHaveBeenCalled()
 })
 it('资源说明关闭再打开默认回到工具目录，仍不进行身份发现',async()=>{
  mount(MCPAccessPreview,{attachTo:document.body,global:{plugins:[Antd]}});await click('工具与资源');await click('元数据资源');expect(document.querySelector('.ant-modal [role="tab"][aria-selected="true"]')?.textContent).toBe('元数据资源')
  await new DOMWrapper(document.querySelector('.ant-modal-close')!).trigger('click');await flushPromises();await click('工具与资源');expect(document.querySelector('.ant-modal [role="tab"][aria-selected="true"]')?.textContent).toBe('工具目录');expect(scope().text()).toContain('不代表当前身份已发现');expect(fetch).not.toHaveBeenCalled()
 })
 it('9工具与元数据资源互斥展示，不伪装当前身份的实际发现',async()=>{
  mount(MCPAccessPreview,{attachTo:document.body,global:{plugins:[Antd]}});await click('工具与资源');expect(scope().text()).toContain('不代表当前身份已发现');expect(document.querySelectorAll('.ant-modal .ant-table-row')).toHaveLength(9)
  const tab=Array.from(document.querySelectorAll<HTMLElement>('[role=tab]')).find(e=>e.textContent==='元数据资源')!;tab.click();await flushPromises();expect(scope().text()).toContain('starbeacon://catalog/capabilities');expect(fetch).not.toHaveBeenCalled()
 })
})

 describe('响应动作名单核对示例',()=>{
  it('排队任务绑定同一合成核对摘要与授权时间，仍不代表真实执行',async()=>{
   const router=await routing('/work?task=task_action_pending&device_id=device_hq#response'),wrapper=mount(ResponseActionsPreview,{props:{state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await vi.waitFor(()=>expect(scope().text()).toContain('平台授权时未命中有效保护名单'))
   const queued=wrapper.findComponent(TaskTable).props('items').find(row=>row.id==='task_action_pending')!
   expect(validResponseProtection(queued.response_protection,queued.kind,queued.response_action!.requested_at,queued.response_action!.expires_at)).toBe(true)
   expect(queued.response_protection!.check_sha256).toBe(await goJSONDigest(queued.response_protection!.check));expect(scope().text()).toContain('不构成真实授权');expect(fetch).not.toHaveBeenCalled()
   await click('关闭',document.querySelector('.ant-modal')!);expect(router.currentRoute.value.query.task).toBeUndefined();expect(router.currentRoute.value.query.device_id).toBe('device_hq');expect(router.currentRoute.value.hash).toBe('#response')
  })
  it.each(['task_action_unknown','task_does_not_exist'])('%s 不冒充已有名单核对记录',async task=>{
   const router=await routing('/work?task='+task);mount(ResponseActionsPreview,{props:{state:'data'},attachTo:document.body,global:{plugins:[Antd,router]}});await flushPromises()
   expect(scope().text()).toContain(task==='task_action_unknown'?'该历史任务没有名单核对记录':'所选任务不在当前合成示例范围内');expect(scope().text()).not.toContain('平台授权时未命中有效保护名单');expect(fetch).not.toHaveBeenCalled()
  })
 })
