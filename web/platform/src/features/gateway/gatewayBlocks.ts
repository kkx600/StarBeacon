import { cursorQuery } from '@starbeacon/shared/pagination.ts';
import { session } from '../../session';

export interface GatewaySettings {
  revision: number;
  enabled: boolean;
  per_minute: number;
}
export interface GatewayFollowUp {
  plugin_id: string;
  generation: number;
  connector_id: string;
  config_sha256: string;
  target_side: 'source' | 'destination';
  ttl_seconds: number;
}
export interface GatewayDevice extends Omit<GatewayFollowUp, 'target_side' | 'ttl_seconds'> {
  device_id: string;
  version: number;
  max_ttl_seconds: number;
}
export interface GatewayDefinition {
  name: string;
  enabled: boolean;
  trigger: 'rule' | 'review';
  sensor_id: string;
  registration_id: string;
  rule_id: string;
  rule_revision: string;
  scope: { sources: string[]; destinations: string[] };
  lease_seconds: number;
  valid_until: string;
  follow_up?: GatewayFollowUp;
}
export interface GatewayPolicy {
  id: string;
  revision: number;
  definition: GatewayDefinition;
}
export interface GatewayFlow {
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  transport: 'tcp' | 'udp';
}
export interface GatewayObservation {
  state: 'paused' | 'continued' | 'unknown';
  code: string;
  interface: string;
  started_at: string;
  finished_at: string;
  egress_packets: number;
  original_packets: number;
  reconnect?: GatewayFlow;
}
export interface GatewayRecord {
  id: string;
  event_id: string;
  raw_sha256: string;
  policy_id: string;
  policy_revision: number;
  assessment_revision?: number;
  sensor_id: string;
  registration_id: string;
  trigger: 'rule' | 'review';
  state: 'pending' | 'denied' | 'authorized';
  code: string;
  flow: GatewayFlow;
  observed_at: string;
  created_at: string;
  authorized_at?: string;
  lease_until?: string;
  task_id?: string;
  task_state?: string;
  gateway_result?: { request_id: string; lease_until: string; verified_at: string; observation?: GatewayObservation };
  follow_up_state: 'none' | 'pending' | 'issued' | 'skipped';
  follow_up_code: string;
  follow_up_task_id?: string;
  follow_up_task_state?: string;
}
export interface GatewayPage<T> {
  items: T[];
  next_cursor: string;
}
export interface GatewayRecords extends GatewayPage<GatewayRecord> {
  enabled: boolean;
  online_gateways: number;
  last_day: { total: number; paused: number; continued: number; unknown: number; protected: number };
}

export const gatewayID = (value: unknown): value is string =>
  typeof value === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value);
const digest = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const counter = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
const timestamp = (value: unknown) => typeof value === 'string' && Number.isFinite(Date.parse(value));

function validSettings(value: GatewaySettings) {
  return (
    value &&
    counter(value.revision) &&
    typeof value.enabled === 'boolean' &&
    Number.isInteger(value.per_minute) &&
    value.per_minute >= 1 &&
    value.per_minute <= 60
  );
}

export async function readGatewaySettings(signal: AbortSignal) {
  const result = await session.api.request<GatewaySettings>('/gateway-block/settings', { signal });
  if (!validSettings(result)) throw new Error('网关设置响应不完整，请刷新后核对。');
  return result;
}

export async function saveGatewaySettings(revision: number, enabled: boolean, perMinute: number, signal: AbortSignal) {
  const result = await session.api.request<GatewaySettings>('/gateway-block/settings', {
    method: 'PUT',
    body: { expected_revision: revision, enabled, per_minute: perMinute },
    signal,
  });
  if (
    !validSettings(result) ||
    result.revision !== revision + 1 ||
    result.enabled !== enabled ||
    result.per_minute !== perMinute
  )
    throw new Error('网关设置回执不一致，请刷新后核对。');
  return result;
}

function validPolicy(row: GatewayPolicy) {
  const d = row?.definition;
  return (
    gatewayID(row?.id) &&
    counter(row.revision) &&
    row.revision > 0 &&
    d &&
    typeof d.name === 'string' &&
    typeof d.enabled === 'boolean' &&
    ['rule', 'review'].includes(d.trigger) &&
    [d.sensor_id, d.registration_id].every(gatewayID) &&
    typeof d.rule_id === 'string' &&
    typeof d.rule_revision === 'string' &&
    counter(d.lease_seconds) &&
    timestamp(d.valid_until) &&
    [d.scope?.sources, d.scope?.destinations].every(
      list => Array.isArray(list) && list.every(v => typeof v === 'string'),
    ) &&
    (!d.follow_up ||
      ([d.follow_up.plugin_id, d.follow_up.connector_id].every(gatewayID) &&
        counter(d.follow_up.generation) &&
        digest(d.follow_up.config_sha256) &&
        ['source', 'destination'].includes(d.follow_up.target_side) &&
        counter(d.follow_up.ttl_seconds)))
  );
}

export async function saveGatewayPolicy(
  id: string,
  revision: number,
  definition: GatewayDefinition,
  signal: AbortSignal,
) {
  const result = await session.api.request<GatewayPolicy>('/gateway-block/policies/' + encodeURIComponent(id), {
    method: 'PUT',
    body: { expected_revision: revision, definition },
    signal,
  });
  if (!validPolicy(result) || result.id !== id || result.revision !== revision + 1)
    throw new Error('网关策略回执不一致，请刷新后核对。');
  return result;
}

function validFlow(v: GatewayFlow) {
  return (
    v &&
    typeof v.source_ip === 'string' &&
    typeof v.destination_ip === 'string' &&
    [v.source_port, v.destination_port].every(port => counter(port) && port > 0 && port <= 65535) &&
    (v.transport === 'tcp' || v.transport === 'udp')
  );
}
function validRecord(v: GatewayRecord) {
  return (
    v &&
    [v.id, v.policy_id, v.sensor_id, v.registration_id].every(gatewayID) &&
    digest(v.event_id) &&
    digest(v.raw_sha256) &&
    counter(v.policy_revision) &&
    ['rule', 'review'].includes(v.trigger) &&
    ['pending', 'denied', 'authorized'].includes(v.state) &&
    ['none', 'pending', 'skipped', 'issued'].includes(v.follow_up_state) &&
    validFlow(v.flow) &&
    timestamp(v.created_at) &&
    timestamp(v.observed_at) &&
    [v.task_id, v.follow_up_task_id].every(id => id === undefined || gatewayID(id)) &&
    (!v.gateway_result ||
      (v.gateway_result.request_id === v.id &&
        timestamp(v.gateway_result.verified_at) &&
        timestamp(v.gateway_result.lease_until) &&
        (!v.gateway_result.observation ||
          (['paused', 'continued', 'unknown'].includes(v.gateway_result.observation.state) &&
            timestamp(v.gateway_result.observation.started_at) &&
            timestamp(v.gateway_result.observation.finished_at) &&
            counter(v.gateway_result.observation.egress_packets) &&
            counter(v.gateway_result.observation.original_packets) &&
            (!v.gateway_result.observation.reconnect || validFlow(v.gateway_result.observation.reconnect))))))
  );
}
function validPage<T extends { id: string }>(value: GatewayPage<T>, limit: number) {
  return (
    value &&
    Array.isArray(value.items) &&
    value.items.length <= limit &&
    new Set(value.items.map(row => row?.id)).size === value.items.length &&
    (value.next_cursor === '' || (gatewayID(value.next_cursor) && value.items.at(-1)?.id === value.next_cursor))
  );
}

export async function readGatewayRecords(cursor: string, limit: number, signal: AbortSignal): Promise<GatewayRecords> {
  const result = await session.api.request<GatewayRecords>('/gateway-block/requests' + cursorQuery(cursor, limit), {
    signal,
  });
  if (
    !validPage(result, limit) ||
    !result.items.every(validRecord) ||
    typeof result.enabled !== 'boolean' ||
    !counter(result.online_gateways) ||
    !result.last_day ||
    ![
      result.last_day.total,
      result.last_day.paused,
      result.last_day.continued,
      result.last_day.unknown,
      result.last_day.protected,
    ].every(counter)
  )
    throw new Error('网关记录响应不完整，请刷新后核对。');
  return result;
}

export async function readGatewayRecord(id: string, signal: AbortSignal): Promise<GatewayRecord> {
  const result = await session.api.request<GatewayRecord>('/gateway-block/requests/' + encodeURIComponent(id), {
    signal,
  });
  if (!validRecord(result) || result.id !== id) throw new Error('网关记录身份不一致。');
  return result;
}

export async function readGatewayPolicies(cursor: string, limit: number, signal: AbortSignal) {
  const result = await session.api.request<GatewayPage<GatewayPolicy>>(
    '/gateway-block/policies' + cursorQuery(cursor, limit),
    { signal },
  );
  if (!validPage(result, limit) || !result.items.every(validPolicy))
    throw new Error('网关策略响应不完整，请刷新后核对。');
  return result;
}

export async function readGatewayDevices(sensor: string, registration: string, signal: AbortSignal) {
  const query = new URLSearchParams({ sensor_id: sensor, registration_id: registration });
  const result = await session.api.request<{ items: GatewayDevice[] }>('/gateway-block/plugins?' + query.toString(), {
    signal,
  });
  if (
    !Array.isArray(result?.items) ||
    result.items.length > 8 ||
    new Set(result.items.map(device => device?.plugin_id)).size !== result.items.length ||
    !result.items.every(
      device =>
        [device?.plugin_id, device?.device_id, device?.connector_id].every(gatewayID) &&
        digest(device.config_sha256) &&
        counter(device.generation) &&
        device.generation > 0 &&
        counter(device.version) &&
        device.version > 0 &&
        counter(device.max_ttl_seconds) &&
        device.max_ttl_seconds >= 30 &&
        device.max_ttl_seconds <= 3600,
    )
  )
    throw new Error('可预授权的插件目录不可核对。');
  return result.items;
}

export function formatGatewayFlow(flow: GatewayFlow) {
  const endpoint = (ip: string, port: number) => (ip.includes(':') ? '[' + ip + ']' : ip) + ':' + port;
  return endpoint(flow.source_ip, flow.source_port) + ' → ' + endpoint(flow.destination_ip, flow.destination_port);
}

export const gatewayCodes: Record<string, string> = {
  gateway_block_disabled: '网关阻断已停用',
  gateway_setting_changed: '网关设置已变化',
  policy_changed: '策略修订或授权期限已变化',
  authorization_revoked: '授权人已停用或权限已变化',
  assessment_changed: '原研判已变化',
  protected_endpoint: '保护名单拦截',
  rate_limited: '达到限额',
  active_flow_lease: '原连接已有生效租约',
  observation_expired: '观测或签发时窗已过期',
  observation_unavailable: '缺少可用的出侧观察证据',
  traffic_continued: '出侧仍有流量',
  observer_changed: '网关观察绑定已变化',
  observer_unavailable: '观察口不可用',
  window_short: '租约不足以覆盖观察窗口',
  packet_loss: '出侧采样不完整',
  packet_format: '同端点报文无法完整识别',
  egress_idle: '观察窗内缺少出侧采样',
  device_changed: '插件部署或设备绑定已变化',
  target_cooldown: '目标已有租约或仍在冷却期',
  policy_authorized: '已按当前策略授权',
};
