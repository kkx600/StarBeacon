import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import MetricBar from '../packages/shared/src/components/MetricBar.vue';

describe('共享指标条', () => {
  it('只有大于零的风险数值着色', () => {
    const wrapper = mount(MetricBar, {
      props: {
        items: [
          { label: '待研判', value: 0, tone: 'warning' },
          { label: '高危告警', value: '0.0%', tone: 'danger' },
          { label: '净变动', value: -1, tone: 'danger' },
          { label: '在线探针', value: 8, tone: 'success' },
          { label: '需关注', value: '1,248', tone: 'warning' },
          { label: '严重告警', value: 2, tone: 'danger' },
        ],
      },
    });
    const values = wrapper.findAll('.metric-value');
    expect(values.map(value => value.text())).toEqual(['0', '0.0%', '-1', '8', '1,248', '2']);
    expect(values.map(value => value.attributes('data-tone'))).toEqual([
      undefined,
      undefined,
      undefined,
      undefined,
      'warning',
      'danger',
    ]);
  });

  it('缺测显示破折号与原因，并省略单位和风险色', () => {
    const wrapper = mount(MetricBar, {
      props: {
        items: [
          { label: '落盘', value: null, suffix: 'TB', tone: 'warning', missingReason: '尚未取得落盘统计' },
          { label: '缺测', value: '未获取', note: '观测范围' },
          { label: '无效值', value: Number.NaN, tone: 'danger' },
        ],
      },
    });
    expect(wrapper.findAll('.metric-item[data-missing]')).toHaveLength(3);
    expect(wrapper.findAll('.metric-note').map(note => note.text())).toEqual([
      '尚未取得落盘统计',
      '未取得观测值',
      '未取得观测值',
    ]);
    for (const value of wrapper.findAll('.metric-value')) {
      expect(value.text()).toBe('—');
      expect(value.attributes('aria-label')).toBe('无数据');
      expect(value.attributes('data-tone')).toBeUndefined();
    }
    expect(wrapper.find('.metric-suffix').exists()).toBe(false);
  });

  it('格式化容量与速率，保留明确的单位并支持深色表面', () => {
    const wrapper = mount(MetricBar, {
      props: {
        dark: true,
        items: [
          { label: '流量', value: 1500, suffix: 'Mbit/s' },
          { label: '空间', value: '1536', suffix: 'MiB' },
          { label: '保留期', value: 10, suffix: '天' },
        ],
      },
    });
    expect(wrapper.findAll('.metric-suffix').map(suffix => suffix.text())).toEqual(['Gbit/s', 'GiB', '天']);
    expect(wrapper.findAll('.metric-value').map(value => value.text())).toEqual(['1.5Gbit/s', '1.5GiB', '10天']);
    expect(wrapper.attributes('data-dark')).toBe('true');
  });
});
