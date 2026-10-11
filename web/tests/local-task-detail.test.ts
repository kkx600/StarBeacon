import {defineComponent,h} from 'vue'
import {createRouter,createMemoryHistory} from 'vue-router'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '@starbeacon/shared/ant.ts'
import {ApiClient,ApiError} from '@starbeacon/shared/api.ts'
import ReplayWorkspace from '@starbeacon/shared/components/ReplayWorkspace.vue'
import TaskTable from '@starbeacon/shared/components/TaskTable.vue'
import RuleEditor from '@starbeacon/shared/components/RuleEditor.vue'
import {principal,task,sample,click,deferred,rules,writeRule} from './fixtures'

const request=vi.fn(),api=new ApiClient('/api/local/v1');api.request=request
const localID='localtask_19a1'
function archive(id=localID){
 const started=new Date(Date.now()-60000).toISOString(),finished=new Date(Date.now()-59000).toISOString()
 return {...task,id,kind:'rules.replay',origin:'local',acknowledged:true,retention_protected:false,state:'succeeded',created_at:new Date(Date.now()-61000).toISOString(),expires_at:new Date(Date.now()-30000).toISOString(),retain_until:new Date(Date.now()+86400000).toISOString(),receipt:{command_id:id,command_sha256:'a'.repeat(64),state:'succeeded',started_at:started,finished_at:finished,result:{}}}
}
beforeEach(()=>{request.mockReset();request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?archive():path==='/replay/samples'?{items:[sample],available:true}:{items:[]}))})
async function workspace(url='/network?view=tasks&task='+localID,view:'samples'|'tasks'='tasks'){
 const router=createRouter({history:createMemoryHistory(),routes:[{path:'/:pathMatch(.*)*',component:defineComponent({render:()=>h('div')})}]})
 await router.push(url);await router.isReady()
 const wrapper=mount(ReplayWorkspace,{props:{api,principal,local:true,view},global:{plugins:[registerAnt,router]},attachTo:document.body});await flushPromises()
 return {wrapper,router}
}
describe('采集器历史任务详情',()=>{
 it('不依赖最近列表，执行已截止仍可读取；刷新、关闭和路由往返保持原任务',async()=>{
  const {wrapper,router}=await workspace('/network?view=tasks&task='+localID+'&source=replay#trace')
  expect(request.mock.calls.some(call=>call[0]==='/tasks/'+localID)).toBe(true);expect(wrapper.findAll('.ant-table')).toHaveLength(1);expect(document.body.textContent).toContain('记录保留截止')
  await click('刷新详情');expect(request.mock.calls.filter(call=>call[0]==='/tasks/'+localID)).toHaveLength(2)
  await router.replace('/network?view=tasks&source=replay#trace');await flushPromises();expect(wrapper.findComponent(TaskTable).exists()).toBe(false);expect(document.body.querySelector('.ant-modal')).toBeNull()
  await router.push('/network?view=tasks&task='+localID+'&source=replay#trace');await flushPromises();router.back();await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBeUndefined());router.forward();await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBe(localID));await flushPromises()
  await click('关闭');await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBeUndefined());expect(router.currentRoute.value.query).toEqual({view:'tasks',source:'replay'});expect(router.currentRoute.value.hash).toBe('#trace');wrapper.unmount()
 })
 it('列表错误不阻断档案；详情失败、缺失或错标识时移除旧内容',async()=>{
  request.mockImplementation((path:string)=>path.startsWith('/tasks/')?Promise.resolve(archive()):Promise.reject(new Error('列表不可用')))
  const {wrapper}=await workspace();expect(document.body.textContent).toContain(localID)
  for(const result of [null,[],{}, {...archive(),id:'localtask_other'}, {...archive(),sensor_id:'UPPER'}, {...archive(),kind:'shell'}, {...archive(),state:'queued'}, {...archive(),origin:'external'}, {...archive(),acknowledged:undefined}, {...archive(),retention_protected:undefined}, {...archive(),retention_protected:true}, {...archive(),receipt:[]}, {...archive(),retain_until:'bad'}, {...archive(),retain_until:new Date(Date.now()-1).toISOString()}, {...archive(),expires_at:archive().created_at}, {...archive(),receipt:{...archive().receipt,command_id:'localtask_other'}}, {...archive(),receipt:{...archive().receipt,command_sha256:'bad'}}, {...archive(),receipt:{...archive().receipt,state:'failed'}}, {...archive(),receipt:{...archive().receipt,result:[]}}, {...archive(),receipt:{...archive().receipt,started_at:'bad'}}, {...archive(),receipt:{...archive().receipt,finished_at:'bad'}}, {...archive(),rule_resolution:[]}, {...archive(),kind:'diagnostics'}]){
   request.mockResolvedValueOnce(result);await click('刷新详情');expect(document.body.textContent).toContain('详情未能完整返回');expect(document.body.textContent).not.toContain('记录保留截止')
  }
  request.mockRejectedValueOnce(new ApiError(404,'not_found','本地任务不存在或已过留存期'));await click('刷新详情');expect(document.body.textContent).toContain('本地任务不存在或已过留存期');expect(document.body.textContent).not.toContain('记录保留截止');wrapper.unmount()
 })
 it('待确认或待核实的过期计划继续只读追溯，不能据此生成设备操作',async()=>{
  const started=new Date(Date.now()-181*86400000).toISOString()
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?{...archive(),id:'task_remote',kind:'response.block',origin:'platform',acknowledged:false,retention_protected:true,retain_until:new Date(Date.now()-86400000).toISOString(),receipt:{...archive().receipt,command_id:'task_remote',started_at:started}}:{items:[]}))
  const {wrapper}=await workspace('/network?view=tasks&task=task_remote');expect(document.body.textContent).toContain('任务记录受执行确认保护');expect(document.body.textContent).toContain('保留截止是原计划期限');expect(document.body.textContent).toContain('执行回执')
  expect([...document.body.querySelectorAll('button')].some(button=>['解除封禁','回读设备','取消任务'].includes(button.textContent?.trim()??''))).toBe(false);expect(request.mock.calls.every(call=>!call[1]?.method||call[1].method==='GET')).toBe(true);wrapper.unmount()
 })
 it('查看近期记录写入独立详情链接；列表只呈现一张业务表格',async()=>{
  request.mockImplementation((path:string)=>Promise.resolve(path.startsWith('/tasks/')?archive():{items:path==='/tasks'?[archive()]:[]}))
  const {wrapper,router}=await workspace('/network?view=tasks');await click('查看');await vi.waitFor(()=>expect(router.currentRoute.value.query.task).toBe(localID));expect(document.body.textContent).toContain('记录保留截止');expect(wrapper.findAll('.ant-table')).toHaveLength(1);wrapper.unmount()
 })
 it('受理入口链接精确任务，保持来源筛选和片段；样本视图不读取旧详情',async()=>{
  const {wrapper,router}=await workspace('/network?view=samples&task=task_old&source=pcap#trace','samples')
  expect(request.mock.calls.some(call=>call[0].startsWith('/tasks/'))).toBe(false)
  await click('重放测试');await writeRule(wrapper.getComponent(RuleEditor),rules)
  request.mockResolvedValueOnce({id:localID});await click('执行重放');await click('查看任务记录');await vi.waitFor(()=>expect(router.currentRoute.value.query).toEqual({view:'tasks',task:localID,source:'pcap'}));expect(router.currentRoute.value.hash).toBe('#trace')
  await wrapper.setProps({view:'tasks'});expect(document.body.textContent).toContain('记录保留截止');wrapper.unmount()
 })
 it('不合法和多值任务链接不调用接口，只读账号不打开管理员档案',async()=>{
  for(const value of ['UPPER','bad%2Fid',localID+'&task=other']){
   request.mockClear();const {wrapper}=await workspace('/network?view=tasks&task='+value);expect(document.body.textContent).toContain('任务链接无效');expect(request.mock.calls.some(call=>call[0].startsWith('/tasks/'))).toBe(false);wrapper.unmount()
  }
  const {wrapper}=await workspace();await wrapper.setProps({principal:{...principal,role:'viewer'}});expect(wrapper.findComponent(TaskTable).exists()).toBe(false);expect(document.body.querySelector('.ant-modal')).toBeNull();wrapper.unmount()
 })
 it('切换任务、工作视图、账号和卸载取消异步读取，阻止旧档案恢复',async()=>{
  const late=deferred<unknown>();request.mockImplementation((path:string)=>path==='/tasks/'+localID?late.promise:Promise.resolve(path.startsWith('/tasks/')?archive('localtask_other'):{items:[]}))
  const {wrapper,router}=await workspace();const signal=request.mock.calls.find(call=>call[0]==='/tasks/'+localID)![1].signal as AbortSignal
  await router.push('/network?view=tasks&task=localtask_other');await flushPromises();expect(signal.aborted).toBe(true);late.resolve(archive());await flushPromises();expect(wrapper.getComponent(TaskTable).props('detail')!.item?.id).toBe('localtask_other')
  const after=deferred<unknown>();request.mockReturnValueOnce(after.promise);wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const active=request.mock.lastCall![1].signal as AbortSignal
  await wrapper.setProps({view:'samples'});expect(active.aborted).toBe(true);after.resolve(archive());await flushPromises();expect(document.body.textContent).not.toContain('记录保留截止')
  await wrapper.setProps({view:'tasks'});request.mockReturnValueOnce(deferred().promise);wrapper.getComponent(TaskTable).vm.$emit('refreshDetail');await flushPromises();const account=request.mock.lastCall![1].signal as AbortSignal
  await wrapper.setProps({principal:null});expect(account.aborted).toBe(true);expect(document.body.querySelector('.ant-modal')).toBeNull();wrapper.unmount()
 })
})
