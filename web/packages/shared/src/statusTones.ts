import { statusTerms, type StatusTone } from './terms.ts';
import type { Alert, modelJobStates, Sensor } from './types';

export type StatusToneMap = Readonly<Record<string, StatusTone>>;

// 各业务状态键显式对应标准词的色调。未知状态使用中性色，由调用方展示原值或无数据的原因。
export function statusTone(tones: StatusToneMap, state: unknown): StatusTone {
  return typeof state === 'string' && Object.hasOwn(tones, state) ? tones[state]! : 'neutral';
}

export const alertSeverityTones = {
  critical: statusTerms.严重,
  high: statusTerms.高危,
  medium: statusTerms.中危,
  low: statusTerms.低危,
  unknown: 'neutral',
} as const satisfies Record<Alert['severity'] | 'critical', StatusTone>;

export const alertWorkflowTones = {
  open: statusTerms.待研判,
  investigating: statusTerms.研判中,
  linked: statusTerms.已关联事件,
  false_positive: statusTerms.误报,
  closed: statusTerms.已关闭,
} as const satisfies StatusToneMap;

export const sensorConnectionTones = {
  online: statusTerms.在线,
  offline: statusTerms.离线,
  disabled: statusTerms.停用,
} as const satisfies Record<Sensor['status'], StatusTone>;

export const sensorHealthTones = {
  healthy: statusTerms.正常,
  degraded: statusTerms.需关注,
  abnormal: statusTerms.异常,
  missing: statusTerms.无数据,
} as const satisfies StatusToneMap;

export const taskStateTones = {
  queued: statusTerms.排队中,
  delivered: 'info',
  running: statusTerms.运行中,
  retrying: statusTerms.重试中,
  succeeded: statusTerms.已完成,
  failed: statusTerms.失败,
  unknown: statusTerms.结果未知,
  expired: statusTerms.已过期,
  cancelled: statusTerms.已取消,
} as const satisfies StatusToneMap;

export const modelJobTones = {
  queued: statusTerms.排队中,
  running: statusTerms.运行中,
  succeeded: statusTerms.已完成,
  failed: statusTerms.失败,
  refused: 'warning',
  incomplete: statusTerms.不完整,
  uncertain: statusTerms.结果未知,
  cancelled: statusTerms.已取消,
} as const satisfies Record<keyof typeof modelJobStates, StatusTone>;
