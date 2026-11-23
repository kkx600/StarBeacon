import { describe, expect, it } from 'vitest';
import { formatTime } from '../packages/shared/src/types';
import { formatNumber } from '../packages/shared/src/utils/format';

describe('界面时间格式', () => {
  it('按浏览器时区补齐日期、时间和可选毫秒', () => {
    const date = new Date(2026, 0, 2, 0, 4, 5, 7);
    expect(formatTime(date)).toBe('2026-01-02 00:04:05');
    expect(formatTime(date.toISOString())).toBe('2026-01-02 00:04:05');
    expect(formatTime(date, { fraction: 'milliseconds' })).toBe('2026-01-02 00:04:05.007');
  });

  it('指定 UTC 后同一时刻的不同输入得到同一时间', () => {
    expect(formatTime('2026-01-02T03:04:05+08:00', { timeZone: 'UTC' })).toBe('2026-01-01 19:04:05');
    expect(formatTime('2026-01-01T19:04:05Z', { timeZone: 'UTC' })).toBe('2026-01-01 19:04:05');
    expect(formatTime('2026-01-01T19:04:05.987654321Z', { timeZone: 'UTC', fraction: 'milliseconds' })).toBe(
      '2026-01-01 19:04:05.987',
    );
    expect(formatTime('2026-01-02T03:04:05.987654321+08:00', { timeZone: 'UTC', fraction: 'source' })).toBe(
      '2026-01-01 19:04:05.987654321',
    );
  });

  it('缺测和无效时间分别给出提示', () => {
    expect(formatTime()).toBe('未获取');
    expect(formatTime(null)).toBe('未获取');
    expect(formatTime('')).toBe('未获取');
    expect(formatTime('invalid')).toBe('时间无效');
    expect(formatTime(new Date(Number.NaN))).toBe('时间无效');
  });
});

describe('界面数字格式', () => {
  it('统一正负数和零值的千分位显示', () => {
    expect(formatNumber(0)).toBe('0');
    expect(formatNumber(1248)).toBe('1,248');
    expect(formatNumber(-1234.125)).toBe('-1,234.125');
  });

  it('大整数保留全部有效位', () => {
    expect(formatNumber(18446744073709551615n)).toBe('18,446,744,073,709,551,615');
  });
});
