import { describe, expect, it } from 'vitest';
import { mount } from '@vue/test-utils';
import { Pagination, Select } from 'ant-design-vue';
import {
  defaultPageSize,
  pageOf,
  pageSizeOptions,
  tablePagination,
  totalText,
} from '../packages/shared/src/pagination';
import ListPager from '../packages/shared/src/components/ListPager.vue';

const rows = Array.from({ length: 45 }, (_, index) => index + 1);
const button = (wrapper: ReturnType<typeof mount>, label: string) => {
  const match = wrapper.findAll('button').find(item => item.text().replace(/\s/g, '') === label);
  expect(match, `按钮 ${label} 应存在`).toBeDefined();
  return match!;
};

describe('分页标准', () => {
  it('总数文案按中文千分位显示，接受数字、大整数和字符串', () => {
    expect(totalText(0)).toBe('共 0 条');
    expect(totalText(1234567)).toBe('共 1,234,567 条');
    expect(totalText(12345678901234567890n)).toBe('共 12,345,678,901,234,567,890 条');
    // 超出安全整数范围的总数以字符串传入，不能丢失精度。
    expect(totalText('9007199254740993')).toBe('共 9,007,199,254,740,993 条');
  });

  it('取当前页记录，页码越界时落在第一页或最后一页', () => {
    expect(pageOf(rows, 1, 20)).toEqual(rows.slice(0, 20));
    expect(pageOf(rows, 2, 20)).toEqual(rows.slice(20, 40));
    expect(pageOf(rows, 3, 20)).toEqual([41, 42, 43, 44, 45]);
    expect(pageOf(rows, 0, 20)).toEqual(rows.slice(0, 20));
    expect(pageOf(rows, -3, 20)).toEqual(rows.slice(0, 20));
    expect(pageOf(rows, 99, 20)).toEqual([41, 42, 43, 44, 45]);
    expect(pageOf(rows.slice(0, 40), 3, 20)).toEqual(rows.slice(20, 40));
    expect(pageOf([], 5, 20)).toEqual([]);
  });

  it('表格内置分页使用统一的默认条数、可选条数和总数文案', () => {
    expect(defaultPageSize).toBe(20);
    expect(pageSizeOptions).toEqual([10, 20, 50, 100]);
    const pagination = tablePagination();
    expect(pagination).toMatchObject({
      defaultPageSize: 20,
      pageSizeOptions: ['10', '20', '50', '100'],
      showSizeChanger: true,
      size: 'small',
    });
    expect(pagination.showTotal(8)).toBe('共 8 条');
  });
});

describe('列表分页条：页码分页', () => {
  it('显示总数，翻页只更新页码', async () => {
    const wrapper = mount(ListPager, { props: { page: 2, pageSize: 20, total: 1234 } });
    expect(wrapper.classes()).not.toContain('list-pager-cursor');
    expect(wrapper.get('.ant-pagination-total-text').text()).toBe('共 1,234 条');
    expect(wrapper.find('.list-pager-summary').exists()).toBe(false);

    await wrapper.get('.ant-pagination-next').trigger('click');
    expect(wrapper.emitted('update:page')).toEqual([[3]]);
    expect(wrapper.emitted('update:pageSize')).toBeUndefined();
  });

  it('切换每页条数时先更新条数，再回到第 1 页', () => {
    const wrapper = mount(ListPager, { props: { page: 4, pageSize: 20, total: 1234 } });
    wrapper.getComponent(Pagination).vm.$emit('change', 4, 50);
    expect(wrapper.emitted('update:pageSize')).toEqual([[50]]);
    expect(wrapper.emitted('update:page')).toEqual([[1]]);
    expect(wrapper.emitted('change')).toEqual([[1, 50]]);
  });

  it('未给出总数时按 0 条显示', () => {
    const wrapper = mount(ListPager, { props: { page: 1 } });
    expect(wrapper.get('.ant-pagination-total-text').text()).toBe('共 0 条');
  });
});

describe('列表分页条：游标分页', () => {
  it('摘要显示当前页、本页条数，接口给出总数时追加总数', async () => {
    const wrapper = mount(ListPager, { props: { mode: 'cursor', page: 3, pageSize: 50, count: 50 } });
    expect(wrapper.classes()).toContain('list-pager-cursor');
    expect(wrapper.find('.ant-pagination').exists()).toBe(false);
    expect(wrapper.get('.list-pager-summary').text()).toBe('第 3 页 · 本页 50 条');

    await wrapper.setProps({ total: 1234 });
    expect(wrapper.get('.list-pager-summary').text()).toBe('第 3 页 · 本页 50 条 · 共 1,234 条');

    await wrapper.setProps({ count: undefined, total: undefined });
    expect(wrapper.get('.list-pager-summary').text()).toBe('第 3 页');
  });

  it('上一页与下一页按是否有前后页禁用，点击发出对应事件', async () => {
    const wrapper = mount(ListPager, { props: { mode: 'cursor', page: 2, count: 20, hasPrevious: true } });
    expect(button(wrapper, '上一页').attributes('disabled')).toBeUndefined();
    expect(button(wrapper, '下一页').attributes('disabled')).toBeDefined();

    await button(wrapper, '上一页').trigger('click');
    await button(wrapper, '下一页').trigger('click');
    expect(wrapper.emitted('previous')).toHaveLength(1);
    expect(wrapper.emitted('next')).toBeUndefined();

    await wrapper.setProps({ hasNext: true });
    await button(wrapper, '下一页').trigger('click');
    expect(wrapper.emitted('next')).toHaveLength(1);

    await wrapper.setProps({ disabled: true });
    expect(button(wrapper, '上一页').attributes('disabled')).toBeDefined();
    expect(button(wrapper, '下一页').attributes('disabled')).toBeDefined();
    expect(wrapper.getComponent(Select).props('disabled')).toBe(true);
  });

  it('每页条数使用统一选项，切换后回到第 1 页', () => {
    const wrapper = mount(ListPager, { props: { mode: 'cursor', page: 5, pageSize: 20, count: 20, hasNext: true } });
    const select = wrapper.getComponent(Select);
    expect(select.props('value')).toBe(20);
    expect(select.props('options')).toEqual([
      { value: 10, label: '10 条/页' },
      { value: 20, label: '20 条/页' },
      { value: 50, label: '50 条/页' },
      { value: 100, label: '100 条/页' },
    ]);

    select.vm.$emit('change', '100');
    expect(wrapper.emitted('update:pageSize')).toEqual([[100]]);
    expect(wrapper.emitted('update:page')).toEqual([[1]]);
  });
});
