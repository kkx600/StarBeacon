import { describe, expect, it } from 'vitest';
import { statusTerms, toneOf, type StatusTone } from '../packages/shared/src/terms';

const tones: StatusTone[] = ['critical', 'danger', 'warning', 'success', 'info', 'neutral'];

describe('状态用语标准', () => {
  it('标准用语取到登记的色调', () => {
    expect(toneOf('严重')).toBe('critical');
    expect(toneOf('高危')).toBe('danger');
    expect(toneOf('需关注')).toBe('warning');
    expect(toneOf('启用')).toBe('success');
    expect(toneOf('停用')).toBe('neutral');
    expect(toneOf('运行中')).toBe('info');
    expect(toneOf('待复核')).toBe('warning');
    expect(toneOf('无数据')).toBe('neutral');
    expect(toneOf('证据不足')).toBe('warning');
    for (const [term, tone] of Object.entries(statusTerms)) expect(toneOf(term)).toBe(tone);
  });

  it('非标准说法、空串和带空白的写法不算标准用语', () => {
    for (const value of ['已启用', '已停用', '调查中', '待核对', '不可观测', '暂不可用', '', ' 启用', '启用 ']) {
      expect(toneOf(value), value).toBeUndefined();
    }
  });

  it('对象原型上的属性名不算标准用语', () => {
    for (const value of ['constructor', 'toString', 'hasOwnProperty', 'valueOf', '__proto__']) {
      expect(toneOf(value), value).toBeUndefined();
    }
  });

  it('每个标准用语的色调都在允许的六种之内', () => {
    expect(Object.keys(statusTerms).length).toBeGreaterThan(0);
    for (const [term, tone] of Object.entries(statusTerms)) expect(tones, term).toContain(tone);
  });
});
