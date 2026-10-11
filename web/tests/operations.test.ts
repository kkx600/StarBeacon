import {beforeEach,describe,expect,it,vi} from 'vitest'
import {defineComponent,h,shallowRef,type Ref} from 'vue'
import {flushPromises,mount} from '@vue/test-utils'
import {registerAnt} from '../packages/shared/src/ant'
import PlatformHealth from '../platform/src/features/operations/PlatformHealth.vue'
import AuditTable from '../platform/src/features/operations/AuditTable.vue'
import AuditDetail from '../platform/src/features/operations/AuditDetail.vue'
import {useAudits,type AuditCategory} from '../platform/src/features/operations/useAudits'
import {actionLabel} from '../platform/src/features/operations/audits'
import type {AuditRecord,PlatformHealth as Health} from '../packages/shared/src/types'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../platform/src/session',()=>({session:{api:{request}}}))
beforeEach(()=>{request.mockReset()})
const global={plugins:[registerAnt]}
const record:AuditRecord={id:'9223372036854775806',username:'operator',action:'inventory.assets.save',object_id:'obj_1',request_id:'request_1',source_ip:'192.0.2.10',user_agent:'验收浏览器',created_at:'2026-10-01T00:00:00Z'}
const health:Health={services:{postgresql:'ready',redis:'ready',elasticsearch:'unavailable'},observed_at:'2026-10-02T00:00:00Z',runtime:{version:'test',commit:'test-commit',observed_at:'2026-10-02T00:00:00Z',cpu_percent:12.5,memory_percent:null,disk_percent:22.4,heap_bytes:'1230000',goroutines:25,errors:['memory_unavailable']}}
function host(category:Ref<AuditCategory>){let state!:ReturnType<typeof useAudits>;const wrapper=mount(defineComponent({setup(){state=useAudits(category);return()=>h('div')}}));return {state,wrapper}}

describe('运行状态',()=>{
  it('展示真实可用性和缺测，资源格式不会产生长数字',async()=>{
    request.mockResolvedValue(health);const wrapper=mount(PlatformHealth,{global});expect(wrapper.text()).toContain('正在读取数据');await flushPromises()
    expect(wrapper.text()).toContain('部分平台依赖不可用');expect(wrapper.text()).toContain('内存指标不可用');expect(wrapper.text()).toContain('未获取');expect(wrapper.text()).toContain('1.23 MB');expect(wrapper.text()).toContain('test-commit');expect(wrapper.find('.ant-table').exists()).toBe(false)
    request.mockResolvedValue({...health,services:{custom:'ready'},runtime:{...health.runtime,errors:[]}});await wrapper.get('button').trigger('click');await flushPromises();expect(wrapper.text()).toContain('custom');expect(wrapper.text()).not.toContain('部分平台依赖不可用')
  })
  it('读取失败可重试，离开后迟到响应不写入页面',async()=>{
    request.mockRejectedValueOnce(new Error('连接超时')).mockRejectedValueOnce('offline').mockResolvedValue(health);const wrapper=mount(PlatformHealth,{global});await flushPromises();expect(wrapper.get('[role=alert]').text()).toContain('连接超时')
    await wrapper.findAll('button').find(button=>button.text().replace(/\s/g,'')==='重试')!.trigger('click');await flushPromises();expect(wrapper.text()).toContain('运行状态读取失败')
    await wrapper.get('button').trigger('click');await flushPromises();expect(wrapper.text()).toContain('test-commit')
    const signal=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(signal.aborted).toBe(true)
  })
})

describe('审计筛选和游标',()=>{
  it('固定检索时间窗翻页，切换日志类型清除不适用条件',async()=>{
    request.mockResolvedValue({items:[record],next_cursor:record.id});const category=shallowRef<AuditCategory>('operations'),{state}=host(category);await flushPromises();const initial=new URL('https://test'+request.mock.lastCall?.[0]);expect(initial.searchParams.get('limit')).toBe('20')
    state.next();await flushPromises();const next=new URL('https://test'+request.mock.lastCall?.[0]);expect(next.searchParams.get('end')).toBe(initial.searchParams.get('end'));expect(next.searchParams.get('cursor')).toBe(record.id)
    state.previous();await flushPromises();state.previous();expect(state.cursors.value).toEqual([''])
    state.search({username:'operator',action:record.action,success:'false',hours:24});await flushPromises();expect(request.mock.lastCall?.[0]).toContain('action=inventory.assets.save');expect(request.mock.lastCall?.[0]).not.toContain('success=')
    category.value='logins';await flushPromises();expect(request.mock.lastCall?.[0]).toContain('/audits/logins?');expect(request.mock.lastCall?.[0]).toContain('success=');expect(request.mock.lastCall?.[0]).not.toContain('action=');expect(state.cursors.value).toEqual([''])
    state.refresh();await flushPromises();expect(state.result.value.items).toEqual([record])
  })
  it('取消旧查询并提供失败重试，不在加载中推进游标',async()=>{
    let reject!:(value:Error)=>void;request.mockImplementationOnce(()=>new Promise((_yes,no)=>{reject=no})).mockRejectedValueOnce(new Error('检索超时')).mockRejectedValueOnce('offline')
    const {state,wrapper}=host(shallowRef<AuditCategory>('operations')),signal=request.mock.lastCall?.[1].signal as AbortSignal;state.next();expect(state.cursors.value).toEqual(['']);state.refresh();await flushPromises();expect(signal.aborted).toBe(true);expect(state.error.value).toBe('检索超时')
    reject(new Error('旧错误'));await flushPromises();expect(state.error.value).toBe('检索超时');state.refresh();await flushPromises();expect(state.error.value).toBe('审计日志读取失败');const live=request.mock.lastCall?.[1].signal as AbortSignal;wrapper.unmount();expect(live.aborted).toBe(true)
  })
})

describe('日志列表和详情',()=>{
  it('操作和登录结果有业务文案，64 位标识保持字符串',async()=>{
    const wrapper=mount(AuditTable,{props:{category:'operations',records:[record]},global});expect(wrapper.text()).toContain('保存资产修订');await wrapper.get('button').trigger('click');expect(wrapper.emitted('view')?.[0]?.[0]).toEqual(record)
    await wrapper.setProps({category:'logins',records:[{...record,success:true},{...record,id:'second',success:false},{...record,id:'third',source_ip:'',username:''}]});expect(wrapper.text()).toContain('验证通过');expect(wrapper.text()).toContain('验证失败');expect(wrapper.text()).toContain('未获取');expect(actionLabel('future.action')).toBe('其他操作')
  })
  it('通知和模型写入的审计名称保持业务含义',async()=>{
    const wrapper=mount(AuditTable,{props:{category:'operations',records:[{...record,action:'models.provider.test'},{...record,id:'notification',action:'notifications.delivery.retry'}]},global})
    expect(wrapper.text()).toContain('提交模型连接验证');expect(wrapper.text()).toContain('提交通知人工重试');expect(wrapper.text()).not.toContain('其他操作')
  })
  it('详情展示来源和验证阶段，不把登录验证当作会话成功',async()=>{
    const wrapper=mount(AuditDetail,{props:{record:null},global,attachTo:document.body});expect(document.body.textContent).not.toContain('凭据验证结果不代表')
    await wrapper.setProps({record:{...record,success:false,phase:'password_verification'}});await flushPromises();expect(document.body.textContent).toContain('凭据验证结果不代表会话一定创建成功');expect(document.body.textContent).toContain(record.id);expect(document.body.textContent).toContain('密码验证');expect(document.body.textContent).toContain('验收浏览器')
    await wrapper.setProps({record:{...record,object_id:'',source_ip:'',request_id:'',user_agent:'',success:true,phase:'other'}});await flushPromises();expect(document.body.textContent).toContain('验证通过');expect(document.body.textContent).toContain('未提供')
    await wrapper.setProps({record:{...record,action:'users.password.recover',username:'database:owner',reason:'值班管理员凭据遗失'}});await flushPromises();expect(document.body.textContent).toContain('离线恢复管理员密码');expect(document.body.textContent).toContain('值班管理员凭据遗失');expect(document.body.textContent).toContain('操作原因');expect(document.body.textContent).toContain('database:owner')
    ;(document.body.querySelector('.ant-modal-close') as HTMLButtonElement).click();await flushPromises();expect(wrapper.emitted('close')).toHaveLength(1)
  })
})
