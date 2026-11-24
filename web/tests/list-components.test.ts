import { mount } from '@vue/test-utils';
import { Select as ASelect } from 'ant-design-vue';
import { h } from 'vue';
import { describe, expect, it, vi } from 'vitest';
import ListFilters from '../packages/shared/src/components/ListFilters.vue';
import ListTable from '../packages/shared/src/components/ListTable.vue';
import TimeRangeField from '../packages/shared/src/components/TimeRangeField.vue';
import { tablePagination } from '../packages/shared/src/pagination';

describe('共享列表筛选', () => {
  it('将字段和操作放在同一网格，按需显示高级筛选', () => {
    const wrapper = mount(ListFilters, {
      props: { label: '会话检索', wide: true },
      slots: {
        default: '<label><span>关键词</span><input /></label>',
        actions: '<button>查询</button>',
        advanced: '<label><span>协议</span><input /></label>',
      },
    });
    const filters = wrapper.get('.filter-grid-wide');
    expect(wrapper.attributes('aria-label')).toBe('会话检索');
    expect(filters.get('label').text()).toBe('关键词');
    expect(filters.get('.filter-buttons button').text()).toBe('查询');
    expect(wrapper.get('.advanced-filters label').text()).toBe('协议');
  });

  it('默认使用检索条件名称，省略空的操作与高级区域', () => {
    const wrapper = mount(ListFilters);
    expect(wrapper.attributes('aria-label')).toBe('检索条件');
    expect(wrapper.find('.filter-buttons').exists()).toBe(false);
    expect(wrapper.find('.advanced-filters').exists()).toBe(false);
  });
});

describe('共享时间范围字段', () => {
  it('预设选择更新绑定值并为控件关联标签', () => {
    const wrapper = mount(TimeRangeField, {
      props: { presets: ['最近 1 小时', '最近 24 小时'], preset: '最近 24 小时' },
    });
    const select = wrapper.getComponent(ASelect);
    expect(wrapper.get('label').text()).toBe('时间范围');
    expect(wrapper.get('input').attributes('id')).toBe(wrapper.get('label').attributes('for'));
    expect(select.props('options')).toEqual([
      { label: '最近 1 小时', value: '最近 1 小时' },
      { label: '最近 24 小时', value: '最近 24 小时' },
    ]);
    select.vm.$emit('update:value', '最近 1 小时');
    expect(wrapper.emitted('update:preset')).toEqual([['最近 1 小时']]);
  });

  it('本地时间输入保留秒、字段标识和接口约定，分别更新两端时间', async () => {
    const wrapper = mount(TimeRangeField, {
      props: { idPrefix: 'test-range', required: true, endHint: '结束时刻不包含在查询内。' },
    });
    expect(wrapper.get('label[for="test-range-start"]').text()).toBe('开始时间（本地时间）');
    expect(wrapper.get('label[for="test-range-end"]').text()).toBe('结束时间（本地时间）');
    expect(wrapper.text()).toContain('结束时刻不包含在查询内。');
    const start = wrapper.get('#test-range-start');
    const end = wrapper.get('#test-range-end');
    expect(start.attributes('type')).toBe('datetime-local');
    expect(end.attributes('step')).toBe('1');
    await start.setValue('2026-11-24T09:00:01');
    await end.setValue('2026-11-24T10:00:01');
    expect(wrapper.emitted('update:start')).toEqual([['2026-11-24T09:00:01']]);
    expect(wrapper.emitted('update:end')).toEqual([['2026-11-24T10:00:01']]);
  });
});

describe('共享列表表格', () => {
  const data = [
    { id: 'record-002', title: '月度汇总', count: 2 },
    { id: 'record-001', title: '每日汇总', count: 1 },
  ];
  type Row = (typeof data)[number];
  const columns = [
    { key: 'id', dataIndex: 'id', title: '编号' },
    { key: 'title', dataIndex: 'title', title: '名称', ellipsis: true },
    { key: 'count', dataIndex: 'count', title: '条数', sorter: (a: Row, b: Row) => a.count - b.count },
  ];
  const ReportTable = ListTable<Row, (typeof columns)[number]>;

  it('保留表头、单元格插槽和排序事件，默认交由外部控制分页', async () => {
    const onChange = vi.fn();
    const wrapper = mount(ReportTable, {
      props: { columns, dataSource: data },
      attrs: { onChange },
      slots: {
        bodyCell: ({ column, record, text }) =>
          column.key === 'title' ? h('button', { title: record.title }, record.title) : text,
      },
    });
    expect(wrapper.findAll('thead th').map(cell => cell.text())).toEqual(['编号', '名称', '条数']);
    expect(wrapper.get('tbody tr').attributes('data-row-key')).toBe('record-002');
    expect(wrapper.get('tbody button').attributes('title')).toBe('月度汇总');
    expect(wrapper.find('.ant-pagination').exists()).toBe(false);
    await wrapper.get('.ant-table-column-sorters').trigger('click');
    expect(wrapper.get('tbody tr').attributes('data-row-key')).toBe('record-001');
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('内置模式沿用共享分页配置并显示总数，即使只有一页', () => {
    const wrapper = mount(ReportTable, { props: { columns, dataSource: data, pagination: tablePagination() } });
    expect(wrapper.get('.ant-pagination-total-text').text()).toBe('共 2 条');
    expect(wrapper.get('tbody tr').text()).toContain('月度汇总');
  });
});
