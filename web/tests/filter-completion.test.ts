import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { registerAnt } from '../packages/shared/src/ant'
import AdvancedFilter from '../platform/src/features/alerts/AdvancedFilter.vue'
import { completionRange, insertSearchField, readSearchFields, suggestFields, type SearchField } from '../platform/src/features/alerts/filterCompletion'

const { request } = vi.hoisted(() => ({ request: vi.fn() }))
vi.mock('../platform/src/session', () => ({ session: { api: { request } } }))
const fields: SearchField[] = [
  { name: 'source.ip', label: '源 IP', type: 'ip', aliases: ['ip.src'], operators: ['exists', '==', 'in'] },
  { name: 'http.path', label: 'HTTP 路径', type: 'string', aliases: ['http.request.uri'], operators: ['exists', '==', 'contains'] },
  { name: 'http.method', label: 'HTTP 方法', type: 'keyword', aliases: ['http.request.method'], operators: ['exists', '=='] },
  { name: 'tcp', label: 'TCP 协议', type: 'protocol', aliases: [], operators: ['exists'] },
]
const wrappers: VueWrapper[] = []
beforeEach(() => { request.mockReset(); request.mockResolvedValue({ fields }) })
afterEach(() => { for (const wrapper of wrappers.splice(0)) wrapper.unmount(); document.body.innerHTML = '' })
async function editor(value = '') {
  const wrapper = mount(AdvancedFilter, { props: { modelValue: value, disabled: false, 'onUpdate:modelValue': (model: string) => { void wrapper.setProps({ modelValue: model }) } }, global: { plugins: [registerAnt] }, attachTo: document.body })
  wrappers.push(wrapper); await flushPromises()
  return wrapper
}

describe('类型化检索字段与插入边界', () => {
  it('字段清单复制数组并拒绝损坏、重复和未知运算', () => {
    const parsed = readSearchFields({ fields }); parsed[0]!.aliases.push('alias')
    expect(fields[0]!.aliases).toEqual(['ip.src'])
    const invalid: unknown[] = [null, {}, { fields: {} }, { fields: Array(257).fill(fields[0]) }, { fields: [null] }, { fields: [fields[0], fields[0]] }]
    for (const change of [{ name: 'tenant-id' }, { label: '' }, { type: 'script' }, { aliases: ['bad alias'] }, { aliases: null }, { operators: ['script'] }, { operators: null }]) invalid.push({ fields: [{ ...fields[0], ...change }] })
    for (const value of invalid) expect(() => readSearchFields(value)).toThrow()
    expect(readSearchFields({ fields: [] })).toEqual([])
  })
  it('引号、转义、无效光标和空前缀不提供错误补全', () => {
    for (const cursor of [-1, 0.5, 9]) expect(completionRange('http.p', cursor)).toBeUndefined()
    expect(completionRange('http.path contains "http.p', 26)).toBeUndefined()
    expect(suggestFields('http.path == "a\\\"http.p', 23, fields)).toEqual([])
    expect(suggestFields('', 0, fields)).toEqual([])
    expect(suggestFields('', 0, fields, true)).toHaveLength(4)
    expect(suggestFields('http.request.u', 14, fields).map(f => f.name)).toEqual(['http.path'])
    expect(suggestFields('HTTP.P', 6, fields).map(f => f.name)).toEqual(['http.path'])
  })
  it('替换光标字段同时保留已有操作、后续条件和原始文本', () => {
    expect(insertSearchField('http.p contains "/api" and tcp', 6, fields[1]!).value).toBe('http.path contains "/api" and tcp')
    expect(insertSearchField('http.path contains "/api"', 6, fields[1]!).value).toBe('http.path contains "/api"')
    expect(insertSearchField('(ip.s)', 5, fields[0]!).value).toBe('(source.ip == )')
    expect(insertSearchField('tcp', 3, fields[0]!).value).toBe('tcp and source.ip == ')
    expect(insertSearchField('tcp ', 4, fields[0]!).value).toBe('tcp and source.ip == ')
    expect(insertSearchField('tcp and ', 8, fields[0]!).value).toBe('tcp and source.ip == ')
    expect(insertSearchField('', 0, fields[3]!).value).toBe('tcp')
    expect(insertSearchField('', 0, { ...fields[1]!, operators: ['contains'] }).value).toBe('http.path contains ')
    expect(insertSearchField('', 0, { ...fields[0]!, operators: [] }).value).toBe('source.ip == ')
    expect(suggestFields('', 0, Array.from({ length: 12 }, (_, i) => ({ ...fields[0]!, name: `field${i}` })), true)).toHaveLength(8)
  })
})

describe('高级检索输入交互', () => {
  it('按前缀补全、方向键循环、回车选择和 Esc 关闭', async () => {
    const wrapper = await editor()
    const textarea = wrapper.get('textarea'); textarea.element.focus()
    await textarea.setValue('http.'); await flushPromises()
    expect(wrapper.findAll('.filter-suggestions button')).toHaveLength(2)
    await textarea.trigger('keydown', { key: 'ArrowUp' })
    expect(document.activeElement?.textContent).toContain('http.method')
    await wrapper.get('.filter-suggestions button:last-child').trigger('keydown', { key: 'ArrowDown' })
    expect(document.activeElement?.textContent).toContain('http.path')
    await wrapper.get('.filter-suggestions button:first-child').trigger('click'); await flushPromises()
    expect(wrapper.props('modelValue')).toBe('http.path == ')
    expect(wrapper.find('.filter-suggestions').exists()).toBe(false)
    await textarea.setValue('ip.s'); await textarea.trigger('keydown', { key: 'Enter' }); await flushPromises()
    expect(wrapper.props('modelValue')).toBe('source.ip == ')
    await textarea.trigger('keydown', { key: ' ', code: 'Space', ctrlKey: true }); await flushPromises()
    expect(wrapper.find('.filter-suggestions').exists()).toBe(true)
    await textarea.trigger('keydown', { key: 'Escape' }); await flushPromises()
    expect(wrapper.find('.filter-suggestions').exists()).toBe(false)
  })
  it('真实焦点离开、禁用和不完整目录均不允许插入', async () => {
    const wrapper = await editor('http.')
    const textarea = wrapper.get('textarea'); textarea.element.focus(); await flushPromises()
    expect(wrapper.find('.filter-suggestions').exists()).toBe(true)
    await textarea.trigger('blur', { relatedTarget: document.body }); await flushPromises()
    expect(wrapper.find('.filter-suggestions').exists()).toBe(false)
    await wrapper.setProps({ disabled: true }); await textarea.trigger('keydown', { key: ' ', ctrlKey: true })
    expect(wrapper.find('.filter-suggestions').exists()).toBe(false)
    request.mockResolvedValueOnce({ fields: [{ name: 'broken' }] })
    await wrapper.setProps({ disabled: false, dataset: 'context' }); await flushPromises()
    await wrapper.findAll('button').find(b => b.text() === '字段目录')!.trigger('click'); await flushPromises()
    expect(document.body.textContent).toContain('检索字段目录格式无效')
  })
  it('外部条件替换后收敛选择位置，输入法回车不抢占文本提交', async () => {
    const wrapper = await editor('http.')
    const textarea = wrapper.get('textarea'); textarea.element.focus(); await flushPromises()
    await textarea.trigger('keydown', { key: 'ArrowUp' })
    await wrapper.setProps({ modelValue: 'ip.s' }); textarea.element.focus(); await textarea.trigger('click'); await flushPromises()
    await textarea.trigger('keydown', { key: 'Enter', isComposing: true }); await flushPromises()
    expect(wrapper.props('modelValue')).toBe('ip.s')
    await textarea.trigger('keydown', { key: 'Enter' }); await flushPromises()
    expect(wrapper.props('modelValue')).toBe('source.ip == ')
  })
  it('切换数据集和卸载取消请求，旧结果不会恢复原字段', async () => {
    let resolve!: (value: unknown) => void
    request.mockImplementationOnce(() => new Promise(value => { resolve = value }))
    const wrapper = await editor()
    const old = request.mock.calls[0]![1].signal as AbortSignal
    await wrapper.setProps({ dataset: 'context' }); await flushPromises()
    expect(old.aborted).toBe(true); expect(request.mock.lastCall?.[0]).toBe('/traffic/fields')
    resolve({ fields: [{ ...fields[0], name: 'old' }] }); await flushPromises()
    const textarea = wrapper.get('textarea'); textarea.element.focus(); await textarea.setValue('ip.s'); await flushPromises()
    expect(wrapper.text()).toContain('source.ip'); expect(wrapper.text()).not.toContain('old')
    const signal = request.mock.lastCall?.[1].signal as AbortSignal
    wrapper.unmount(); expect(signal.aborted).toBe(true)
  })
})
