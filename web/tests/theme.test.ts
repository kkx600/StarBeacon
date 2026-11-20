import {describe, expect, it} from 'vitest'
import {flushPromises, mount} from '@vue/test-utils'
import {defineComponent, h} from 'vue'
import {Alert, App, Button, ConfigProvider, message, theme} from 'ant-design-vue'
import {appTheme, componentSeeds, palette} from '../packages/shared/src/theme'
import {useFeedback} from '../packages/shared/src/composables/useFeedback'

describe('共享组件配色', () => {
  it('四类提示使用主题指定的浅色表面，正文与页面背景保持中性', async () => {
    const wrapper = mount(ConfigProvider, {
      props: {theme: appTheme},
      slots: {default: () => [...['warning', 'success', 'error', 'info'].map(type => h(Alert, {type: type as 'warning', message: `${type} 状态`, showIcon: true})), h(Button, {type: 'link'}, () => '查看记录')]},
      attachTo: document.body,
    })
    await flushPromises()
    const expected = [palette.warningSurface, palette.successSurface, palette.dangerSurface, palette.infoSurface]
    for (const [index, alert] of wrapper.findAll('.ant-alert').entries()) {
      const rgb = expected[index]!.slice(1).match(/../g)!.map(value => parseInt(value, 16))
      expect(getComputedStyle(alert.element).backgroundColor).toBe(`rgb(${rgb.join(', ')})`)
      expect(getComputedStyle(alert.element.querySelector('.ant-alert-message')!).color).toBe('rgb(41, 52, 61)')
    }
    expect(appTheme.token.colorBgLayout).toBe('#f4f4f4')
    expect(appTheme.token.colorBgContainer).toBe('#ffffff')
    expect(getComputedStyle(wrapper.get('.ant-btn-link').element).color).toBe('rgb(47, 84, 235)')
  })

  it('主按钮、开关与选择状态使用主色，交互色由默认算法生成', () => {
    const tokens = theme.defaultAlgorithm({...theme.defaultSeed, ...appTheme.token})
    expect(componentSeeds).toEqual({colorPrimary: '#2f54eb', colorSuccess: '#3a9e50', colorWarning: '#e08a00', colorError: '#e5484d', colorInfo: '#2f54eb'})
    expect(palette.action).toBe(tokens.colorPrimary)
    expect(palette.actionHover).toBe(tokens.colorPrimaryHover)
    expect(palette.actionActive).toBe(tokens.colorPrimaryActive)
    expect(palette.selectionSurface).toBe(tokens.colorPrimaryBg)
  })

  it('应用内操作消息继承主题，独立组件仍能显示默认消息', async () => {
    let standalone: ReturnType<typeof useFeedback> | undefined
    const fallback = mount(defineComponent({setup() {standalone = useFeedback(); return () => h('div')}}))
    expect(standalone).toBe(message)
    fallback.unmount()
    const Probe = defineComponent({setup() {
      const feedback = useFeedback()
      expect(feedback).not.toBe(message)
      return () => h(Button, {onClick: () => feedback.success('主题消息')}, () => '触发消息')
    }})
    const wrapper = mount(ConfigProvider, {props: {theme: appTheme}, slots: {default: () => h(App, null, {default: () => h(Probe)})}, attachTo: document.body})
    await wrapper.get('button').trigger('click')
    await flushPromises()
    const icon = document.querySelector('.ant-message-success .anticon')!
    expect(icon).not.toBeNull()
    expect(getComputedStyle(icon).color).toBe('rgb(58, 158, 80)')
    expect(document.querySelector('.ant-message-notice-content')?.textContent).toContain('主题消息')
    wrapper.unmount()
  })
})
