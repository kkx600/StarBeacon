import {
  packetCount,
  packetDigest,
  packetID,
  packetObject,
  segmentRetentionLabels,
  type SegmentRetention,
} from '@starbeacon/shared/packetRetention.ts';
import type { SegmentFlowSource } from '@starbeacon/shared/packetInspection.ts';
import { instant } from '@starbeacon/shared/utils/instant.ts';
import {
  defaultTrafficFilters,
  type TrafficDetails,
  type TrafficQuery,
  type TrafficRecord,
  validTrafficResult,
} from './traffic';

export interface FlowSegment {
  schema: 'starbeacon.packet-flow.v1';
  archive_id: string;
  manifest_sha256: string;
  archive_raw_sha256: string;
  run_id: string;
  interface: string;
  network_domain?: string;
  policy_revision?: number;
  window_start: string;
  window_end: string;
  first_observed: string;
  last_observed: string;
  vlan: string;
  retention: SegmentRetention;
  original_bytes: string;
  retained_bytes: string;
  retained_packets: string;
  kernel_drops: string | null;
  limited: boolean;
}

export type PacketFlowRow = TrafficRecord & { details: TrafficDetails & { segment: FlowSegment } };
export interface PacketFlowPage {
  items: PacketFlowRow[];
  page: number;
  page_size: number;
  total: number;
}
export interface PacketFlowQuery extends TrafficQuery {
  endpoint_a: string;
  endpoint_b: string;
  session_retention: string;
}
export const flowWindows = [
  { value: 1, label: '最近 1 小时' },
  { value: 24, label: '最近 24 小时' },
  { value: 168, label: '最近 7 天' },
  { value: 720, label: '最近 30 天' },
  { value: 0, label: '自定义' },
];

export interface PacketFlowFilters {
  hours: number;
  start: string;
  end: string;
  a: string;
  b: string;
  sensor?: string;
  retention?: SegmentRetention;
}
export const defaultFlowFilters = (): PacketFlowFilters => ({ hours: 24, start: '', end: '', a: '', b: '' });

export function flowQuery(filters: PacketFlowFilters, now: number, pageSize: number): PacketFlowQuery {
  const end = filters.hours ? now : Date.parse(filters.end);
  const start = filters.hours ? end - filters.hours * 3600000 : Date.parse(filters.start);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 31 * 86400000)
    throw new Error('请选择有效的起止时间，检索范围最多 31 天。');
  return {
    ...defaultTrafficFilters(),
    event_kind: 'flow_segment',
    start: new Date(start).toISOString(),
    end: new Date(end).toISOString(),
    page: 1,
    page_size: pageSize,
    sensor_id: filters.sensor ?? '',
    endpoint_a: filters.a.trim(),
    endpoint_b: filters.b.trim(),
    session_retention: filters.retention ?? '',
  };
}

function validSegment(value: unknown): value is FlowSegment {
  if (
    !packetObject(value) ||
    value.schema !== 'starbeacon.packet-flow.v1' ||
    !packetID(value.archive_id) ||
    !packetID(value.run_id) ||
    !packetDigest(value.manifest_sha256) ||
    !packetDigest(value.archive_raw_sha256) ||
    typeof value.interface !== 'string' ||
    !/^[^/\\\s\x00-\x1f]{1,15}$/.test(value.interface) ||
    (value.kernel_drops !== null && !packetCount(value.kernel_drops)) ||
    !packetCount(value.original_bytes) ||
    !packetCount(value.retained_bytes) ||
    !packetCount(value.retained_packets) ||
    typeof value.limited !== 'boolean' ||
    typeof value.vlan !== 'string' ||
    (value.vlan &&
      (value.vlan.split(',').length > 8 ||
        !value.vlan.split(',').every(tag => /^(0|[1-9][0-9]{0,3})$/.test(tag) && Number(tag) <= 4095)))
  )
    return false;
  if (value.network_domain !== undefined || value.policy_revision !== undefined) {
    if (
      !packetID(value.network_domain) ||
      typeof value.policy_revision !== 'number' ||
      !Number.isSafeInteger(value.policy_revision) ||
      value.policy_revision < 1
    )
      return false;
  }
  const original = BigInt(value.original_bytes),
    retained = BigInt(value.retained_bytes),
    count = BigInt(value.retained_packets);
  if (
    original === 0n ||
    retained > original ||
    count > retained ||
    count > 1048576n ||
    (count === 0n) !== (retained === 0n) ||
    value.retention !== (retained === 0n ? 'metadata_only' : retained === original ? 'retained' : 'policy_truncated')
  )
    return false;
  const stamp = (key: string) => (typeof value[key] === 'string' ? instant(value[key]) : null);
  const start = stamp('window_start'),
    end = stamp('window_end'),
    first = stamp('first_observed'),
    last = stamp('last_observed');
  return start !== null && end !== null && start <= end && first !== null && last !== null && first <= last;
}

export function validPacketFlowPage(value: unknown, query: PacketFlowQuery, tenant: string): value is PacketFlowPage {
  if (!validTrafficResult(value, query, tenant)) return false;
  const validEndpoint = (item: TrafficRecord['source']) =>
    typeof item.ip === 'string' &&
    /^[0-9a-f:.]{2,45}$/i.test(item.ip) &&
    (item.port === undefined || (Number.isSafeInteger(item.port) && item.port >= 0 && item.port <= 65535));
  return value.items.every(item => {
    const segment = item.details.segment;
    return (
      validSegment(segment) &&
      item.source_generation_id === segment.archive_id &&
      packetID(item.event_id) &&
      packetID(item.sensor_id) &&
      instant(segment.last_observed) === instant(item['@timestamp']) &&
      (!query.sensor_id || query.sensor_id === item.sensor_id) &&
      (!query.session_retention || query.session_retention === segment.retention) &&
      validEndpoint(item.source) &&
      validEndpoint(item.destination) &&
      ['tcp', 'udp'].includes(item.network.transport ?? '')
    );
  });
}

function endpointPort(item: TrafficRecord['source']): string {
  return `${item.ip?.includes(':') ? '[' + item.ip + ']' : item.ip}:${item.port ?? 0}`;
}

export function flowSource(row: PacketFlowRow): SegmentFlowSource | null {
  const segment = row.details.segment;
  if (segment.retention === 'metadata_only') return null;
  const transport = row.network.transport;
  if (transport !== 'tcp' && transport !== 'udp') return null;
  return {
    archiveID: segment.archive_id,
    flow: {
      endpoint_a: endpointPort(row.source),
      endpoint_b: endpointPort(row.destination),
      transport,
      vlan: segment.vlan,
      manifest_sha256: segment.manifest_sha256,
      archive_raw_sha256: segment.archive_raw_sha256,
    },
    count: Number(segment.retained_packets),
    retention: segment.retention,
    interface: segment.interface,
    first: segment.first_observed,
    last: segment.last_observed,
  };
}

export function flowCSV(items: PacketFlowRow[]): string {
  const rows = items.map(row => {
    const segment = row.details.segment;
    return [
      row.event_id,
      row.sensor_id,
      segment.first_observed,
      endpointPort(row.source),
      endpointPort(row.destination),
      row.network.transport,
      segment.original_bytes,
      segment.retained_bytes,
      segmentRetentionLabels[segment.retention],
    ];
  });
  return [['编号', '采集器', '首包时间', '端点 A', '端点 B', '传输协议', '观测字节', '留存字节', '留存状态'], ...rows]
    .map(row => row.map(cell => `"${(cell ?? '').replaceAll('"', '""')}"`).join(','))
    .join('\r\n');
}
