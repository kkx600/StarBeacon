import { mount } from '@vue/test-utils';
import { describe, expect, it } from 'vitest';
import StatusTag from '../packages/shared/src/components/StatusTag.vue';
import {
  alertSeverityTones,
  alertWorkflowTones,
  sensorConnectionTones,
  sensorHealthTones,
  statusTone,
  taskStateTones,
} from '../packages/shared/src/statusTones';
import { taskStates } from '../packages/shared/src/types';

describe('业务状态色调', () => {
  it('分别映射告警严重度和处理状态', () => {
    expect(statusTone(alertSeverityTones, 'critical')).toBe('critical');
    expect(statusTone(alertSeverityTones, 'high')).toBe('danger');
    expect(statusTone(alertSeverityTones, 'medium')).toBe('warning');
    expect(statusTone(alertWorkflowTones, 'open')).toBe('neutral');
    expect(statusTone(alertWorkflowTones, 'investigating')).toBe('info');
  });

  it('连接、健康和任务使用各自的状态键', () => {
    expect(statusTone(sensorConnectionTones, 'online')).toBe('success');
    expect(statusTone(sensorConnectionTones, 'offline')).toBe('neutral');
    expect(statusTone(sensorHealthTones, 'degraded')).toBe('warning');
    expect(statusTone(sensorHealthTones, 'abnormal')).toBe('danger');
    expect(statusTone(taskStateTones, 'running')).toBe('info');
    expect(statusTone(taskStateTones, 'failed')).toBe('danger');
    expect(statusTone(taskStateTones, 'unknown')).toBe('warning');
    for (const code of Object.keys(taskStates)) expect(Object.hasOwn(taskStateTones, code), code).toBe(true);
  });

  it('未知状态、显示文案和原型属性使用中性色', () => {
    for (const state of ['任务执行失败', '严重', 'HIGH', 'constructor', '__proto__', null]) {
      expect(statusTone(alertSeverityTones, state), String(state)).toBe('neutral');
    }
  });
});

describe('共享状态标签', () => {
  it('展示文字变化时色调仍由调用方决定，深色标签可切换', async () => {
    const tag = mount(StatusTag, { props: { value: '高危', tone: 'danger' } });
    expect(tag.text()).toBe('高危');
    expect(tag.attributes('data-tone')).toBe('danger');
    expect(tag.classes()).toEqual(['status-tag']);
    await tag.setProps({ value: '严重', dark: true });
    expect(tag.text()).toBe('严重');
    expect(tag.attributes('data-tone')).toBe('danger');
    expect(tag.attributes('data-dark')).toBe('true');
    await tag.setProps({ value: undefined, tone: 'neutral', dark: false });
    expect(tag.text()).toBe('无数据');
    expect(tag.attributes('data-tone')).toBe('neutral');
    expect(tag.attributes('data-dark')).toBeUndefined();
    expect(tag.get('.status-tag-dot').attributes('aria-hidden')).toBe('true');
    tag.unmount();
  });
});
