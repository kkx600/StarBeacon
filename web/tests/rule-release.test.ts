import {beforeEach, describe, expect, it, vi} from 'vitest'
import {defineComponent, h, type ShallowRef} from 'vue'
import {flushPromises, mount} from '@vue/test-utils'
import {createMemoryHistory, createRouter} from 'vue-router'
import {Checkbox, InputNumber, Modal, Select} from 'ant-design-vue'
import {registerAnt} from '../packages/shared/src/ant'
import type {Principal, SensorTask} from '../packages/shared/src/types'
import {session} from '../platform/src/session'
import {useRuleRelease} from '../platform/src/features/rules/useRuleRelease'
import RuleReleaseDialog from '../platform/src/features/rules/RuleReleaseDialog.vue'
import {button, click, deferred, principal, rulePackage, sensor, task} from './fixtures'

const {request} = vi.hoisted(() => ({request: vi.fn()}))
vi.mock('../platform/src/session', async () => ({session: {api: {request}, current: (await import('vue')).shallowRef(null)}}))
const user = session.current as ShallowRef<Principal | null>
const target = {...sensor, health: {...sensor.health, task_capabilities: ['rules.apply'], registered_rules_sha256: 'c'.repeat(64)}}
function proof(id: string, kind: 'rules.validate' | 'rules.replay', alerts?: number): SensorTask {
  return {...task, id, kind, state: 'succeeded', receipt: {state: 'succeeded', finished_at: new Date().toISOString(), result: {package_id: rulePackage.id, revision: rulePackage.revision, engine_version: '8.0.7', syntax: 'passed', replay: 'completed', rule_mode: 'package', ...(alerts === undefined ? {} : {alert_count: alerts})}}}
}
function evidence() {return [proof('check_1', 'rules.validate'), proof('hit_1', 'rules.replay', 2), proof('miss_1', 'rules.replay', 0)]}
beforeEach(() => {
  user.value = principal; request.mockReset()
  request.mockImplementation((path: string) => Promise.resolve(path === '/sensors' ? {items: [target]} : path.startsWith('/tasks?') ? {items: evidence()} : {id: 'deploy_1'}))
})
function host() {
  let state!: ReturnType<typeof useRuleRelease>
  const wrapper = mount(defineComponent({setup() {state = useRuleRelease(); return () => h('div')}}))
  return {state, wrapper}
}
async function ready(state: ReturnType<typeof useRuleRelease>) {
  await state.open(rulePackage); state.form.sensorID = target.id; await state.loadEvidence()
  Object.assign(state.form, {validation: 'check_1', positive: 'hit_1', negative: 'miss_1', confirmed: true})
}
async function dialog() {
  const router = createRouter({history: createMemoryHistory(), routes: [{path: '/rules', component: {render: () => h('div')}}, {path: '/sensors', component: {render: () => h('div')}}]})
  await router.push('/rules'); await router.isReady()
  let state!: ReturnType<typeof useRuleRelease>
  const wrapper = mount(defineComponent({setup() {state = useRuleRelease(); return () => h(RuleReleaseDialog, {release: state})}}), {global: {plugins: [registerAnt, router]}, attachTo: document.body})
  await state.open(rulePackage); await flushPromises()
  return {state, wrapper, router}
}

describe('规则部署资格与操作一致性', () => {
  it('只允许在线、启用、具有部署能力和有效文件摘要的探针', async () => {
    request.mockResolvedValueOnce({items: [target, {...target, id: 'offline', status: 'offline'}, {...target, id: 'inactive', active: false}, {...target, id: 'no-capability', health: {}}, {...target, id: 'invalid-hash', health: {...target.health, registered_rules_sha256: 'ABC'}}]})
    const {state} = host(); await state.open(rulePackage)
    expect(state.options.value.map(item => item.disabled)).toEqual([false, true, true, true, true]); expect(state.expectedSHA.value).toBe('')
    state.form.sensorID = 'offline'; await state.loadEvidence(); Object.assign(state.form, {validation: 'check_1', positive: 'hit_1', negative: 'miss_1', confirmed: true})
    await state.submit(); expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false); expect(state.error.value).toContain('请选择目标探针')
  })
  it('回执必须属于目标探针、规则包、修订、引擎和有效时间，正反样本不能互换', async () => {
    const {state} = host(); await ready(state)
    const good = evidence(), malformed = [
      {...good[0]!, id: 'foreign-device', sensor_id: 'foreign'}, {...good[0]!, id: 'failed', state: 'failed'},
      {...good[0]!, id: 'receipt-failed', receipt: {...good[0]!.receipt, state: 'failed'}}, {...good[0]!, id: 'code', receipt: {...good[0]!.receipt, code: 'failure'}},
      {...good[0]!, id: 'no-result', receipt: {...good[0]!.receipt, result: undefined}},
      ...['package_id', 'revision', 'engine_version'].map(field => ({...good[0]!, id: field, receipt: {...good[0]!.receipt, result: {...good[0]!.receipt.result, [field]: field === 'revision' ? 3 : 'other'}}})),
      ...['invalid', new Date(Date.now() - 86400001).toISOString(), new Date(Date.now() + 120000).toISOString()].map(finished_at => ({...good[0]!, id: finished_at, receipt: {...good[0]!.receipt, finished_at}})),
      {...good[0]!, id: 'bad-syntax', receipt: {...good[0]!.receipt, result: {...good[0]!.receipt.result, syntax: 'failed'}}},
      ...[{replay: 'not_run'}, {rule_mode: 'registered'}, {alert_count: '1'}, {alert_count: -1}].map((result, i) => ({...good[1]!, id: 'bad-replay-' + i, receipt: {...good[1]!.receipt, result: {...good[1]!.receipt.result, ...result}}})),
    ] as SensorTask[]
    state.tasks.value = [...good, ...malformed]
    expect(state.validations.value.map(item => item.value)).toEqual(['check_1']); expect(state.positives.value.map(item => item.value)).toEqual(['hit_1']); expect(state.negatives.value.map(item => item.value)).toEqual(['miss_1'])
    state.form.positive = 'miss_1'; await state.submit(); expect(state.taskID.value).toBe(''); expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false)
    state.close(); expect(state.validations.value).toEqual([])
  })
  it('提交固定修订、目标文件摘要与三份回执；失败重试保持幂等标识，受理后禁止再次提交', async () => {
    const {state} = host(); await ready(state)
    request.mockRejectedValueOnce(new Error('连接中断，受理结果未知')); await state.submit()
    const first = request.mock.lastCall!; expect(state.error.value).toContain('受理结果未知')
    request.mockResolvedValueOnce({id: 'deploy_1'}); await state.submit(); await state.submit()
    const calls = request.mock.calls.filter(call => call[1]?.method === 'POST')
    expect(calls).toHaveLength(2); expect(calls[1]![1].headers['Idempotency-Key']).toBe(first[1].headers['Idempotency-Key'])
    expect(first[1].body).toEqual({kind: 'rules.apply', package_id: rulePackage.id, revision: 4, validation_task_id: 'check_1', positive_replay_task_id: 'hit_1', negative_replay_task_id: 'miss_1', expected_rules_sha256: 'c'.repeat(64)})
    expect(first[0]).toBe('/sensors/probe_1/tasks'); expect(state.taskID.value).toBe('deploy_1')
    state.changed(); expect(state.taskID.value).toBe(''); expect(state.form.confirmed).toBe(false)
  })
  it('空选择、非法修订、缺少回执或人工确认均不能触发部署', async () => {
    const {state} = host(); await state.submit(); expect(state.error.value).toContain('请选择目标探针')
    await ready(state)
    for (const revision of [0, 5, 1.5, Number.NaN]) {state.form.revision = revision; await state.submit()}
    state.form.revision = 4; state.form.confirmed = false; await state.submit()
    state.form.confirmed = true; state.form.negative = undefined; await state.submit()
    expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false)
  })
  it('切换探针和修订时清除旧回执、确认和受理状态，迟到响应不覆盖当前选择', async () => {
    const {state} = host(); await ready(state)
    const old = deferred<{items: SensorTask[]}>(); request.mockReturnValueOnce(old.promise); const first = state.loadEvidence()
    const oldSignal = request.mock.lastCall![1].signal as AbortSignal
    state.form.sensorID = undefined; await state.loadEvidence(); expect(oldSignal.aborted).toBe(true); expect(state.pending.value).toBe(false)
    old.resolve({items: evidence()}); await first; expect(state.tasks.value).toEqual([]); expect(state.form.confirmed).toBe(false); expect(state.form.validation).toBeUndefined()
    state.form.sensorID = target.id; state.form.revision = 3; request.mockResolvedValueOnce({items: evidence()}); await state.loadEvidence(); expect(state.validations.value).toEqual([])
    state.close(); await state.loadEvidence(); expect(state.selected.value).toBeNull()
  })
  it('连续打开取消旧目录请求；关闭或卸载后不显示迟到数据和错误', async () => {
    const {state, wrapper} = host(), old = deferred<unknown>(); request.mockReturnValueOnce(old.promise); const first = state.open(rulePackage)
    const signal = request.mock.lastCall![1].signal as AbortSignal
    await state.open({...rulePackage, id: 'pkg_other'}); expect(signal.aborted).toBe(true)
    old.reject(new Error('旧目录错误')); await first; expect(state.error.value).toBe(''); expect(state.selected.value?.id).toBe('pkg_other')
    const late = deferred<unknown>(); request.mockReturnValueOnce(late.promise); const opening = state.open(rulePackage); state.close(); late.resolve({items: [target]}); await opening
    expect(state.selected.value).toBeNull(); expect(state.sensors.value).toEqual([])
    wrapper.unmount(); const calls = request.mock.calls.length; await state.open(rulePackage); await state.loadEvidence(); await state.submit(); expect(request.mock.calls).toHaveLength(calls)
  })
  it('权限撤销拒绝写入；目录和任务失败均保留可读错误', async () => {
    const {state} = host(); user.value = {...principal, role: 'viewer'}; await state.open(rulePackage); expect(request).not.toHaveBeenCalled()
    user.value = principal; request.mockRejectedValueOnce('offline'); await state.open(rulePackage); expect(state.error.value).toBe('探针信息读取失败')
    request.mockRejectedValueOnce(new Error('目录连接超时')); await state.open(rulePackage); expect(state.error.value).toBe('目录连接超时')
    await ready(state); user.value = null; await state.submit(); expect(request.mock.calls.some(call => call[1]?.method === 'POST')).toBe(false)
    user.value = principal; request.mockRejectedValueOnce('offline'); await state.loadEvidence(); expect(state.error.value).toBe('验证回执读取失败')
    request.mockRejectedValueOnce(new Error('任务读取超时')); await state.loadEvidence(); expect(state.error.value).toBe('任务读取超时')
    await ready(state); request.mockRejectedValueOnce('offline'); await state.submit(); expect(state.error.value).toBe('发布任务提交失败')
  })
  it('部署期间阻止并发和关闭，离开页面取消请求且不误报迟到受理', async () => {
    const {state, wrapper} = host(); await ready(state)
    const late = deferred<{id: string}>(); request.mockReturnValueOnce(late.promise); const submitting = state.submit()
    const signal = request.mock.lastCall![1].signal as AbortSignal
    await state.submit(); await state.open(rulePackage); await state.loadEvidence(); state.close()
    expect(state.selected.value?.id).toBe(rulePackage.id); expect(request.mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(1)
    wrapper.unmount(); expect(signal.aborted).toBe(true); late.resolve({id: 'deploy_late'}); await submitting; expect(state.taskID.value).toBe('')
  })
  it('离开页面后的失败回执不覆盖界面状态，加载中不能提交', async () => {
    const {state, wrapper} = host(), late = deferred<unknown>(); request.mockReturnValueOnce(late.promise); const opening = state.open(rulePackage)
    await state.submit(); expect(state.error.value).toBe(''); wrapper.unmount(); late.reject(new Error('迟到目录错误')); await opening; expect(state.error.value).toBe('')
    const other = host(); await ready(other.state)
    const fail = deferred<unknown>(); request.mockReturnValueOnce(fail.promise); const posting = other.state.submit(); other.wrapper.unmount(); fail.reject(new Error('迟到提交错误')); await posting; expect(other.state.error.value).toBe('')
  })
})

describe('规则发布对话框', () => {
  it('实际表单选择、历史修订、确认与提交交互保持一致，受理与生效状态明确区分', async () => {
    const {state, wrapper} = await dialog()
    expect(document.body.textContent).toContain('历史修订'); expect(document.body.textContent).toContain('未观察到有效摘要')
    const selects = wrapper.findAllComponents(Select); expect(selects).toHaveLength(4)
    await selects[0]!.setValue(target.id, 'value'); selects[0]!.vm.$emit('change', target.id); await flushPromises()
    expect(document.body.textContent).toContain('c'.repeat(64))
    const revision = wrapper.getComponent(InputNumber); await revision.setValue(3, 'value'); revision.vm.$emit('change', 3); await flushPromises(); expect(state.validations.value).toEqual([])
    await revision.setValue(4, 'value'); revision.vm.$emit('change', 4); await flushPromises()
    for (const [i, id] of ['check_1', 'hit_1', 'miss_1'].entries()) {await selects[i + 1]!.setValue(id, 'value'); selects[i + 1]!.vm.$emit('change', id)}
    await wrapper.getComponent(Checkbox).setValue(true, 'checked'); await click('提交发布任务')
    expect(document.body.textContent).toContain('发布任务已受理'); expect(document.body.textContent).toContain('受理不等于规则已生效'); expect(button('提交发布任务').disabled).toBe(true)
    expect(document.body.querySelector('a[href="/sensors?view=tasks"]')).not.toBeNull()
    wrapper.getComponent(Modal).vm.$emit('cancel'); await flushPromises(); expect(state.selected.value).toBeNull()
  })
  it('失败展示原因且保留用户选择，提交中不能取消弹窗', async () => {
    const {state, wrapper} = await dialog(); await ready(state)
    request.mockRejectedValueOnce(new Error('设备规则摘要已发生变化')); await click('提交发布任务'); expect(document.body.textContent).toContain('设备规则摘要已发生变化'); expect(state.form.positive).toBe('hit_1')
    const late = deferred<unknown>(); request.mockReturnValueOnce(late.promise); button('提交发布任务').click(); await flushPromises()
    const modal = wrapper.getComponent(Modal); expect(modal.props('closable')).toBe(false); expect(modal.props('keyboard')).toBe(false); expect(modal.props('maskClosable')).toBe(false)
    modal.vm.$emit('cancel'); expect(state.selected.value).not.toBeNull(); late.resolve({id: 'deploy_dialog'}); await flushPromises(); expect(state.taskID.value).toBe('deploy_dialog')
  })
})
