import type { StatusTone } from './terms';
import type { Alert, Sensor } from './types';

export type StatusToneMap = Readonly<Record<string, StatusTone>>;

// 色调由各业务对象的状态键决定。收到未知状态时保持中性，交给调用方显示原值或缺测原因。
export function statusTone(tones: StatusToneMap, state: unknown): StatusTone {
  return typeof state === 'string' && Object.hasOwn(tones, state) ? tones[state]! : 'neutral';
}

export const alertSeverityTones = {
  critical: 'critical',
  high: 'danger',
  medium: 'warning',
  low: 'neutral',
  unknown: 'neutral',
} as const satisfies Record<Alert['severity'] | 'critical', StatusTone>;

export const alertWorkflowTones = {
  open: 'neutral',
  investigating: 'info',
  linked: 'neutral',
  false_positive: 'neutral',
  closed: 'neutral',
} as const satisfies StatusToneMap;

export const sensorConnectionTones = {
  online: 'success',
  offline: 'neutral',
  disabled: 'neutral',
} as const satisfies Record<Sensor['status'], StatusTone>;

export const sensorHealthTones = {
  healthy: 'success',
  degraded: 'warning',
  abnormal: 'danger',
  missing: 'neutral',
} as const satisfies StatusToneMap;

export const taskStateTones = {
  queued: 'neutral',
  delivered: 'info',
  running: 'info',
  retrying: 'info',
  succeeded: 'success',
  failed: 'danger',
  unknown: 'warning',
  expired: 'neutral',
  cancelled: 'neutral',
} as const satisfies StatusToneMap;

export const modelJobTones = {
  queued: 'neutral',
  running: 'info',
  succeeded: 'success',
  failed: 'danger',
  refused: 'warning',
  incomplete: 'warning',
  uncertain: 'warning',
  cancelled: 'neutral',
} as const satisfies StatusToneMap;
