import {defineComponent,h,shallowRef} from 'vue'
import {createRouter,createMemoryHistory} from 'vue-router'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '@starbeacon/shared/ant.ts'
import {ApiError} from '@starbeacon/shared/api.ts'
import TaskTable from '@starbeacon/shared/components/TaskTable.vue'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import {principal,task,click,deferred} from './fixtures'
import {webcrypto} from 'node:crypto'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
const user=shallowRef(principal)
vi.mock('../platform/src/session',()=>({session:{api:{request},get current(){return user}}}))
const history=()=>({...task,kind:'diagnostics',state:'succeeded',retain_until:new Date(Date.now()+86400000).toISOString()})
beforeEach(()=>{user.value=principal;request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?history():{items:[]}))})
async function workspace(url='/sensors?view=tasks&task=task_1',sensorId?:string){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:defineComponent({render:()=>h('div')})}]})
 await router.push(url);await router.isReady()
 const wrapper=mount(TaskWorkspace,{props:{sensorId},global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises()
 return {wrapper,router}
}
describe('历史任务详情与链接',()=>{
 it('应用安装档案绑定原任务和持久状态摘要，拒绝其他任务或损坏回执',async()=>{
  vi.stubGlobal('crypto',webcrypto)
  const rules='1'.repeat(64),installed={schema_version:'application-state.v1',deployment_id:task.id,rules_sha256:rules,state_sha256:await goJSONDigest({deployment_id:task.id,rules_sha256:rules}),rule_count:1,installed_at:new Date().toISOString()}
  const row={...history(),kind:'applications.apply',receipt:{...history().receipt,result:installed}}
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?row:{items:[row]}))
  const {wrapper}=await workspace();await vi.waitFor(()=>expect(document.body.textContent).toContain('应用规则安装'))
  expect(document.body.textContent).toContain('采集器已持久安装');expect(document.body.textContent).toContain(rules);expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  for(const value of [{...installed,deployment_id:'task_other'},{...installed,state_sha256:'0'.repeat(64)},{...installed,rule_count:129}]){
   request.mockResolvedValueOnce({...row,receipt:{...row.receipt,result:value}});await click('刷新详情');await vi.waitFor(()=>expect(document.body.textContent).toContain('安装回执与原任务不一致'));expect(document.body.textContent).not.toContain('采集器已持久安装')
  }
  wrapper.unmount()
 })
 it('独立读取列表之外的任务，刷新和重挂载仍打开原标识，关闭保留视图与筛选',async()=>{
  const {wrapper,router}=await workspace('/sensors?view=tasks&task=task_1&source=archive#trace')
  expect(request.mock.calls.some(call=>call[0]==='/tasks/task_1')).toBe(true);expect(wrapper.findAll('.ant-table')).toHaveLength(1)
  expect(document.body.textContent).toContain('记录保留截止');expect(document.body.textContent).toContain('task_1');expect(document.body.querySelectorAll('.ant-modal')).toHaveLength(1)
  await click('刷新详情');expect(request.mock.calls.filter(call=>call[0]==='/tasks/task_1')).toHaveLength(2)
  wrapper.unmount();const mounted=mount(TaskWorkspace,{global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises();expect(request.mock.calls.filter(call=>call[0]==='/tasks/task_1')).toHaveLength(3)
  await click('关闭');await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBeUndefined());expect(router.currentRoute.value.query).toEqual({view:'tasks',source:'archive'});expect(router.currentRoute.value.hash).toBe('#trace');mounted.unmount()
 })
 it('列表读取失败不拦截独立档案；详情失败显示错误而不使用列表冒充',async()=>{
  request.mockImplementation((path:string)=>path.startsWith('/tasks/')?Promise.resolve(history()):Promise.reject(new Error('列表暂不可用')))
  const {wrapper}=await workspace();expect(document.body.textContent).toContain('记录保留截止')
  request.mockRejectedValueOnce(new ApiError(404,'not_found','对象不存在或不可访问'));await click('刷新详情');expect(document.body.textContent).toContain('对象不存在或不可访问');expect(document.body.textContent).not.toContain('记录保留截止');wrapper.unmount()
 })
 it('不完整、错标识、错探针、无效时间和错误授权回执均不得展示为可操作详情',async()=>{
  const {wrapper}=await workspace(undefined,task.sensor_id)
  for(const value of [null,[],{}, {...history(),id:'task_other'}, {...history(),sensor_id:'probe_other'}, {...history(),created_by:'UPPER'}, {...history(),kind:'shell'}, {...history(),state:'unknown_state'}, {...history(),delivery_count:-1}, {...history(),receipt:[]}, {...history(),retain_until:'bad'}, {...history(),retain_until:new Date(Date.now()-1).toISOString()}, {...history(),expires_at:history().created_at}, {...history(),rule_resolution:[]}, {...history(),kind:'response.block'}, {...history(),kind:'response.block',response_action:{}}]){
   request.mockResolvedValueOnce(value);await click('刷新详情');expect(document.body.textContent).toContain('详情未能完整返回');expect(document.body.textContent).not.toContain('记录保留截止')
  }
  wrapper.unmount()
 })
 it('无效、多值链接不向接口发送请求，只读账号不能加载任务档案',async()=>{
  for(const url of ['/sensors?view=tasks&task=UPPER','/sensors?view=tasks&task=bad%2Fid','/sensors?view=tasks&task=task_1&task=task_2']){
   request.mockClear();const {wrapper}=await workspace(url);expect(document.body.textContent).toContain('任务链接无效');expect(request.mock.calls.some(call=>call[0].startsWith('/tasks/'))).toBe(false);wrapper.unmount()
  }
  user.value={...principal,role:'viewer'};request.mockClear();const {wrapper}=await workspace();expect(request.mock.calls.some(call=>call[0].startsWith('/tasks/'))).toBe(false);expect(document.body.querySelector('.ant-modal')).toBeNull();wrapper.unmount()
 })
 it('查看写入查询参数，浏览器前进后退恢复所选任务且不产生第二张业务列表',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?history():{items:[history()]}))
  const {wrapper,router}=await workspace('/sensors?view=tasks&source=archive');await click('查看');await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBe('task_1'));expect(document.body.textContent).toContain('记录保留截止')
  router.back();await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBeUndefined());expect(wrapper.getComponent(TaskTable).props('detail')!.open).toBe(false)
  router.forward();await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBe('task_1'));await flushPromises();expect(wrapper.getComponent(TaskTable).props('detail')!.item?.id).toBe('task_1');expect(wrapper.findAll('.ant-table')).toHaveLength(1);wrapper.unmount()
 })
 it('切换任务、探针或账号时取消旧查询，关闭和卸载阻止迟到内容恢复',async()=>{
  const late=deferred<unknown>();request.mockImplementation((path:string)=>path==='/tasks/task_1'?late.promise:Promise.resolve(path.startsWith('/tasks/')?{...history(),id:'task_2'}:{items:[]}))
  const {wrapper,router}=await workspace();const signal=request.mock.calls.find(call=>call[0]==='/tasks/task_1')![1].signal as AbortSignal
  await router.push('/sensors?view=tasks&task=task_2');await flushPromises();expect(signal.aborted).toBe(true);late.resolve(history());await flushPromises();expect(wrapper.getComponent(TaskTable).props('detail')!.item?.id).toBe('task_2')
  const accountLate=deferred<unknown>();request.mockReturnValueOnce(accountLate.promise);void (wrapper.getComponent(TaskTable).vm.$emit('refreshDetail'));await flushPromises();const activeSignal=request.mock.lastCall![1].signal as AbortSignal
  user.value={...principal,tenant_id:'other'};await flushPromises();expect(activeSignal.aborted).toBe(true);accountLate.resolve({...history(),id:'task_2'});await flushPromises()
  const probeLate=deferred<unknown>();request.mockReturnValueOnce(probeLate.promise);wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const probeSignal=request.mock.lastCall![1].signal as AbortSignal;await wrapper.setProps({sensorId:'probe_other'});expect(probeSignal.aborted).toBe(true);probeLate.reject(new Error('迟到错误'));await flushPromises();expect(document.body.textContent).not.toContain('迟到错误')
  const closeLate=deferred<unknown>();request.mockReturnValueOnce(closeLate.promise);wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const closing=request.mock.lastCall![1].signal as AbortSignal;await click('关闭');await flushPromises();expect(closing.aborted).toBe(true);closeLate.resolve(history());await flushPromises();expect(wrapper.findComponent(TaskTable).exists()).toBe(false);wrapper.unmount()
 })
 it('活动任务有界重试，结束即停止轮询；卸载后取消正在读取的任务',async()=>{
  vi.useFakeTimers();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?{...history(),state:'running'}:{items:[]}))
  const {wrapper}=await workspace();await vi.advanceTimersByTimeAsync(5000);expect(request.mock.calls.filter(call=>call[0]==='/tasks/task_1')).toHaveLength(2)
  request.mockRejectedValue('offline');await vi.advanceTimersByTimeAsync(5000);await vi.advanceTimersByTimeAsync(5000);await vi.advanceTimersByTimeAsync(10000);const count=request.mock.calls.length;await vi.advanceTimersByTimeAsync(30000);expect(request.mock.calls).toHaveLength(count);expect(document.body.textContent).toContain('任务详情读取失败')
  request.mockResolvedValueOnce(history());wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const stoppedCount=request.mock.calls.length;await vi.advanceTimersByTimeAsync(30000);expect(request.mock.calls).toHaveLength(stoppedCount)
  const late=deferred<unknown>();request.mockReturnValueOnce(late.promise);wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const signal=request.mock.lastCall![1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true);late.resolve(history());await flushPromises()
 })
})
