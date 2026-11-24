import { mount } from '@vue/test-utils';
import { describe, expect, it, vi } from 'vitest';
import PageHeader from '../packages/shared/src/components/PageHeader.vue';

describe('共享页面头部', () => {
  it('没有说明和动作时只呈现页面标题', () => {
    const wrapper = mount(PageHeader, { props: { title: '告警列表' } });
    expect(wrapper.get('h1').text()).toBe('告警列表');
    expect(wrapper.find('button').exists()).toBe(false);
    expect(wrapper.find('.page-header-actions').exists()).toBe(false);
    wrapper.unmount();
  });

  it('页面动作保留在标题右侧，说明只在可关闭的弹层显示', async () => {
    const wrapper = mount(PageHeader, {
      props: {
        title: '告警列表',
        description: '核对已入库的检测事件。',
        notice: '仅显示当前租户的数据。',
        helpEntries: [{ id: 1, message: '发生时间', description: '来自检测事件记录。' }],
      },
      slots: { default: '<button type="button">导出</button>' },
      attachTo: document.body,
    });
    try {
      expect(wrapper.get('.page-header-actions button').text()).toBe('导出');
      expect(wrapper.text()).not.toContain('核对已入库');
      const trigger = wrapper.get('button[aria-label="告警列表的说明"]');
      expect(trigger.attributes('aria-expanded')).toBe('false');
      await trigger.trigger('click');
      const content = await vi.waitFor(() => {
        expect(trigger.attributes('aria-expanded')).toBe('true');
        const target = document.getElementById(trigger.attributes('aria-controls') ?? '');
        expect(target).not.toBeNull();
        return target!;
      });
      expect([...content.querySelectorAll('p')].map(line => line.textContent?.trim())).toEqual([
        '核对已入库的检测事件。',
        '仅显示当前租户的数据。',
        '发生时间 来自检测事件记录。',
      ]);
      await trigger.trigger('keydown', { key: 'Escape' });
      expect(trigger.attributes('aria-expanded')).toBe('false');
    } finally {
      wrapper.unmount();
    }
  });
});
