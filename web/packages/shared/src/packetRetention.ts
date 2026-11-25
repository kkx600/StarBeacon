import type { PacketStorage } from './types';

export const retentionModes = { smart: '智能留存', full: '完整保存', alert_only: '只存告警相关' } as const;
export const retentionOrigins = { file: '采集器配置文件', local: '采集器本地设置', platform: '平台签名任务' } as const;
export const segmentRetentionLabels = {
  retained: '窗口内全量留存',
  policy_truncated: '按策略截断',
  metadata_only: '仅元数据',
} as const;
export type SegmentRetention = keyof typeof segmentRetentionLabels;
export type RetentionMode = keyof typeof retentionModes;

export interface PacketRetentionPolicy {
  network_domain: string;
  revision: number;
  mode: RetentionMode;
  encrypted_bytes: number;
  plain_bytes: number;
  dedup_millis: number;
  protect?: string[];
  observe?: string[];
}

export interface PacketRetentionObservation {
  policy: PacketRetentionPolicy;
  sha256: string;
  origin: keyof typeof retentionOrigins;
  task_id?: string;
  applied_at?: string;
}

export interface PacketRetentionChange {
  expected_revision: number;
  expected_sha256: string;
  policy: PacketRetentionPolicy;
}

export interface PacketRetentionStatus {
  state: 'ready' | 'unavailable' | 'not_configured';
  observed_at: string;
  configuration?: PacketRetentionObservation;
  reserved_bytes: string | null;
  quota_bytes: string;
  segment_bytes: string;
  rotate_seconds: number;
}

export interface PacketStorageSensor {
  id: string;
  name: string;
  status: PacketRetentionStatus | null;
  fresh: boolean;
  can_apply: boolean;
}

export interface PacketStorageSettings {
  sensors: PacketStorageSensor[];
  sensors_limited: boolean;
  warm: PacketStorage | null;
  warm_state: 'ready' | 'unavailable' | 'not_configured';
  cold_state: 'unmanaged';
}

export function sameRetentionPolicy(a: PacketRetentionPolicy, b: PacketRetentionPolicy): boolean {
  return (
    a.network_domain === b.network_domain &&
    a.revision === b.revision &&
    a.mode === b.mode &&
    a.encrypted_bytes === b.encrypted_bytes &&
    a.plain_bytes === b.plain_bytes &&
    a.dedup_millis === b.dedup_millis &&
    (a.protect ?? []).join(' ') === (b.protect ?? []).join(' ') &&
    (a.observe ?? []).join(' ') === (b.observe ?? []).join(' ')
  );
}

export function packetObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export const packetID = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
export const packetDigest = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));
const integer = (value: unknown, min: number, max: number): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;
export const packetCount = (value: unknown): value is string =>
  typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= (1n << 64n) - 1n;
const prefixes = (value: unknown) =>
  value === undefined ||
  (Array.isArray(value) &&
    value.length <= 128 &&
    new Set(value).size === value.length &&
    value.every(prefix => typeof prefix === 'string' && /^[0-9a-f:.]+\/[0-9]{1,3}$/i.test(prefix)));

export function validRetentionPolicy(value: unknown): value is PacketRetentionPolicy {
  return (
    packetObject(value) &&
    packetID(value.network_domain) &&
    integer(value.revision, 1, Number.MAX_SAFE_INTEGER) &&
    Object.hasOwn(retentionModes, String(value.mode)) &&
    integer(value.encrypted_bytes, 0, 1024 ** 2) &&
    integer(value.plain_bytes, 64 * 1024, 64 * 1024 ** 2) &&
    (value.dedup_millis === 0 || integer(value.dedup_millis, 10, 500)) &&
    prefixes(value.protect) &&
    prefixes(value.observe)
  );
}

export function validRetentionObservation(value: unknown): value is PacketRetentionObservation {
  if (!packetObject(value) || !validRetentionPolicy(value.policy) || !packetDigest(value.sha256)) return false;
  switch (value.origin) {
    case 'file':
      return value.task_id === undefined && value.applied_at === undefined;
    case 'local':
      return value.task_id === undefined && date(value.applied_at);
    case 'platform':
      return packetID(value.task_id) && date(value.applied_at);
    default:
      return false;
  }
}

export function validRetentionStatus(value: unknown): value is PacketRetentionStatus {
  if (!packetObject(value) || !date(value.observed_at)) return false;
  if (value.state === 'not_configured')
    return (
      value.configuration === undefined &&
      value.reserved_bytes === null &&
      value.quota_bytes === '0' &&
      value.segment_bytes === '0' &&
      value.rotate_seconds === 0
    );
  return (
    ((value.state === 'ready' && validRetentionObservation(value.configuration)) ||
      (value.state === 'unavailable' && value.configuration === undefined)) &&
    (value.reserved_bytes === null || packetCount(value.reserved_bytes)) &&
    packetCount(value.quota_bytes) &&
    packetCount(value.segment_bytes) &&
    integer(value.rotate_seconds, 1, 3600)
  );
}

export function validPacketStorage(value: unknown): value is PacketStorageSettings {
  if (
    !packetObject(value) ||
    !Array.isArray(value.sensors) ||
    value.sensors.length > 500 ||
    typeof value.sensors_limited !== 'boolean' ||
    value.cold_state !== 'unmanaged'
  )
    return false;
  const ids = new Set<string>();
  for (const sensor of value.sensors) {
    if (
      !packetObject(sensor) ||
      !packetID(sensor.id) ||
      ids.has(sensor.id) ||
      typeof sensor.name !== 'string' ||
      typeof sensor.fresh !== 'boolean' ||
      typeof sensor.can_apply !== 'boolean' ||
      (sensor.status !== null && !validRetentionStatus(sensor.status)) ||
      (sensor.fresh && sensor.status === null) ||
      (sensor.can_apply && (!sensor.fresh || sensor.status?.state !== 'ready'))
    )
      return false;
    ids.add(sensor.id);
  }
  if (value.warm_state === 'not_configured' || value.warm_state === 'unavailable') return value.warm === null;
  const warm = value.warm;
  return (
    value.warm_state === 'ready' &&
    packetObject(warm) &&
    typeof warm.backend === 'string' &&
    typeof warm.measured === 'boolean' &&
    ['free_bytes', 'total_bytes', 'floor_bytes', 'limit_bytes', 'archives', 'stored_bytes'].every(key =>
      packetCount(warm[key]),
    ) &&
    (warm.oldest_created_at === null || date(warm.oldest_created_at)) &&
    integer(warm.retention_days, 1, 3650)
  );
}
