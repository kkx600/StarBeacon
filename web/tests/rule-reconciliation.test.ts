import {beforeEach, describe, expect, it, vi} from 'vitest'
import {flushPromises, mount} from '@vue/test-utils'
import {type ShallowRef} from 'vue'
import {message, Popconfirm} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal, RuleResolution} from '../packages/shared/src/types'
import TaskWorkspace from '../platform/src/features/sensors/TaskWorkspace.vue'
import TaskTable from '../packages/shared/src/components/TaskTable.vue'
import {session} from '../platform/src/session'
import {click, closedMessage, deferred, principal, sensor, task} from './fixtures'

const {request} = vi.hoisted(() => ({request: vi.fn()}))
vi.mock('../platform/src/session', async () => ({session: {api: {request}, current: (await import('vue')).shallowRef(null)}}))
const user = session.current as ShallowRef<Principal | null>, global = {plugins: [registerAnt]}
const unknown = {...task, kind: 'rules.apply', state: 'unknown', receipt: {state: 'unknown', code: 'execution_interrupted'}}
const target = {...sensor, health: {...sensor.health, registered_rules_sha256: 'b'.repeat(64), task_capabilities: ['rules.reconcile']}}
const resolution: RuleResolution = {task_id: 'reconcile_1', confirmed_at: new Date().toISOString(), result: {verified: true, active_sha256: 'b'.repeat(64), unknown_task_id: task.id, unknown_command_sha256: 'a'.repeat(64), config_sha256: 'c'.repeat(64), profile_sha256: 'd'.repeat(64), ruleset_stats: [{rules_loaded: 1, rules_failed: 0}]}}
beforeEach(() => {
  user.value = principal; request.mockReset()
  request.mockImplementation((path: string) => Promise.resolve(path === '/sensors' ? {items: [target]} : path.startsWith('/tasks') ? {items: [unknown]} : {id: 'reconcile_1'}))
  vi.spyOn(message, 'success').mockImplementation(closedMessage); vi.spyOn(message, 'error').mockImplementation(closedMessage)
})
async function workspace() {const wrapper = mount(TaskWorkspace, {props: {sensorId: sensor.id}, global, attachTo: document.body}); await flushPromises(); return wrapper}

describe('待核实规则任务', () => {
  it('使用实时设备摘要提交，结果未知时重试保持幂等标识；受理后继续查看实际回执', async () => {
    const wrapper = await workspace(); let fail = true
    request.mockImplementation((path: string, options?: {method?: string}) => options?.method === 'POST' ? fail ? Promise.reject(new Error('受理结果未知')) : Promise.resolve({id: 'reconcile_1'}) : Promise.resolve(path === '/sensors' ? {items: [target]} : {items: [unknown]}))
    await click('核实规则'); await click('提交核实'); expect(message.error).toHaveBeenCalledWith('受理结果未知')
    const first = request.mock.calls.find(call => call[1]?.method === 'POST')!
    fail = false; wrapper.getComponent(TaskTable).vm.$emit('reconcile', unknown); await flushPromises()
    const posts = request.mock.calls.filter(call => call[1]?.method === 'POST'); expect(posts).toHaveLength(2); expect(posts[1]![1].headers).toEqual(first[1].headers)
    expect(first[1].body).toEqual({kind: 'rules.reconcile', unknown_task_id: task.id, expected_rules_sha256: 'b'.repeat(64)}); expect(first[0]).toBe('/sensors/probe_1/tasks')
    expect(message.success).toHaveBeenCalledWith('规则核实任务已受理，请查看设备执行回执'); expect(wrapper.text()).toContain('待核实')
  })
  it('核实完成显示执行时的规则摘要与独立任务，原中断回执仍可查看', async () => {
    const wrapper = mount(TaskTable, {props: {items: [{...unknown, rule_resolution: resolution}], reconcilable: true}, global, attachTo: document.body})
    expect(wrapper.text()).toContain('已核实'); expect(wrapper.text()).not.toContain('核实规则'); await click('查看')
    expect(document.body.textContent).toContain('原中断回执保留'); expect(document.body.textContent).toContain('reconcile_1'); expect(document.body.textContent).toContain('b'.repeat(64)); expect(document.body.textContent).toContain('执行被中断'); expect(document.body.textContent).toContain('核实时规则摘要'); expect(document.body.textContent).not.toContain('设备当前规则已核实'); expect(document.body.textContent).not.toContain('当前摘要')
    expect(wrapper.findAllComponents(Popconfirm)).toHaveLength(0)
  })
  it('已解决、非规则、非待核实和无权限任务不能提交', async () => {
    const wrapper = await workspace(), table = wrapper.getComponent(TaskTable)
    for (const row of [{...unknown, rule_resolution: resolution}, {...unknown, kind: 'diagnostics'}, {...unknown, state: 'succeeded'}, {...unknown, sensor_id: 'other'}]) {table.vm.$emit('reconcile', row); await flushPromises()}
    user.value = {...principal, role: 'viewer'}; table.vm.$emit('reconcile', unknown); await flushPromises()
    expect(request.mock.calls.some(call => call[0] === '/sensors')).toBe(false); expect(wrapper.text()).not.toContain('核实规则')
    const local = mount(TaskTable, {props: {items: [unknown], local: true, reconcilable: true}, global}); expect(local.text()).not.toContain('核实规则')
  })
  it('离线、停用、缺少能力、缺少摘要和已移除的探针均拒绝提交', async () => {
    const wrapper = await workspace()
    for (const items of [[], [{...target, active: false}], [{...target, status: 'offline'}], [{...target, health: {}}], [{...target, health: {...target.health, registered_rules_sha256: 'not-sha'}}]]) {
      request.mockResolvedValueOnce({items}); wrapper.getComponent(TaskTable).vm.$emit('reconcile', unknown); await flushPromises()
      expect(message.error).toHaveBeenLastCalledWith('探针当前不可核实，请核对在线状态、规则摘要和部署授权')
    }
    expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false)
  })
  it('状态变化重新取得幂等标识，标准和非标准错误均可重试', async () => {
    const wrapper = await workspace(), table = wrapper.getComponent(TaskTable); let sha = 'b'.repeat(64)
    request.mockImplementation((path: string, options?: {method?: string}) => options?.method === 'POST' ? Promise.reject('offline') : Promise.resolve(path === '/sensors' ? {items: [{...target, health: {...target.health, registered_rules_sha256: sha}}]} : {items: [unknown]}))
    table.vm.$emit('reconcile', unknown); await flushPromises(); expect(message.error).toHaveBeenCalledWith('规则核实任务提交失败'); const first = request.mock.calls.find(call => call[1]?.method === 'POST')!
    sha = 'a'.repeat(64); table.vm.$emit('reconcile', unknown); await flushPromises(); const last = request.mock.calls.filter(call => call[1]?.method === 'POST').at(-1)!
    expect(last[1].headers['Idempotency-Key']).not.toBe(first[1].headers['Idempotency-Key']); expect(last[1].body.expected_rules_sha256).toBe(sha)
    request.mockRejectedValueOnce(new Error('设备目录读取失败')); table.vm.$emit('reconcile', unknown); await flushPromises(); expect(message.error).toHaveBeenLastCalledWith('设备目录读取失败')
  })
  it('核实中的重复点击不产生并发请求，切换探针取消旧请求并隔离迟到状态', async () => {
    const wrapper = await workspace(), table = wrapper.getComponent(TaskTable), late = deferred<unknown>()
    request.mockReturnValueOnce(late.promise); table.vm.$emit('reconcile', unknown); table.vm.$emit('reconcile', unknown); await flushPromises()
    const signal = request.mock.lastCall![1].signal as AbortSignal; expect(request.mock.calls.filter(call => call[0] === '/sensors')).toHaveLength(1)
    await wrapper.setProps({sensorId: 'other'}); expect(signal.aborted).toBe(true); late.resolve({items: [target]}); await flushPromises()
    expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false); expect(message.success).not.toHaveBeenCalled()
  })
  it('离开页面后取消写请求，迟到受理或失败不会误报', async () => {
    for (const outcome of ['accepted', 'failed']) {
      const wrapper = await workspace(), late = deferred<unknown>()
      request.mockImplementation((path: string, options?: {method?: string}) => options?.method === 'POST' ? late.promise : Promise.resolve(path === '/sensors' ? {items: [target]} : {items: [unknown]}))
      wrapper.getComponent(TaskTable).vm.$emit('reconcile', unknown); await flushPromises(); const signal = request.mock.lastCall![1].signal as AbortSignal
      wrapper.unmount(); expect(signal.aborted).toBe(true); if (outcome === 'accepted') late.resolve({id: 'late'}); else late.reject(new Error('迟到错误'))
      await flushPromises(); expect(message.success).not.toHaveBeenCalled(); expect(message.error).not.toHaveBeenCalled()
    }
  })
})
