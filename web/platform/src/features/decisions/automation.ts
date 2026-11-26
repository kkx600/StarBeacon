import { session } from '../../session';
import { automationLevels, policyID, type AutomationLevel } from './decisionPolicies';
import type { ContinuousRecord, DecisionPlanSummary } from './continuousDecisions';

export const levelOptions = Object.entries(automationLevels).map(([value, label]) => ({
  value: value as AutomationLevel,
  label,
}));
export const automationLocation = { path: '/system/settings', query: { section: 'automation' } };
export interface AutomationSettings {
  revision: number;
  ceiling: AutomationLevel;
  paused: boolean;
}
export interface AutomationScene {
  id: string;
  name: string;
  revision: number;
  active: boolean;
  level: AutomationLevel;
  effective: AutomationLevel;
  small_block_max_seconds: number;
}
export interface AutomationState {
  settings: AutomationSettings;
  scenes: AutomationScene[];
}
export interface PlanMetrics {
  timezone: string;
  start: string;
  end: string;
  triage_count: number;
  triage_mean_ms: number | null;
  pending: number;
  executed: number;
  automatic: number;
  rejected: number;
  protected: number;
}
export const activityKinds = {
  triage: 'AI 研判',
  plan: '处置方案',
  protection: '保护名单拦截',
  review: '方案审核',
  automatic: '自动执行',
  manual: '人工确认执行',
  release: '设备解除回读',
} as const;
export interface PlanActivity {
  id: string;
  at: string;
  kind: keyof typeof activityKinds;
  state: string;
  object: string;
  code: string;
  task_id: string;
}
export interface PlanRow {
  run: ContinuousRecord;
  state: 'awaiting_confirmation';
  task_id: string;
  task_state: string;
}
export interface CursorPage<T> {
  items: T[];
  next_cursor: string;
}
const validLevel = (v: unknown): v is AutomationLevel => typeof v === 'string' && Object.hasOwn(automationLevels, v);
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const date = (v: unknown): v is string => typeof v === 'string' && Number.isFinite(Date.parse(v));
const digest = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
export const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
export function validSettings(v: unknown): v is AutomationSettings {
  return record(v) && count(v.revision) && validLevel(v.ceiling) && typeof v.paused === 'boolean';
}
function validScene(v: unknown): v is AutomationScene {
  return (
    record(v) &&
    policyID(v.id) &&
    typeof v.name === 'string' &&
    count(v.revision) &&
    v.revision > 0 &&
    typeof v.active === 'boolean' &&
    validLevel(v.level) &&
    validLevel(v.effective) &&
    count(v.small_block_max_seconds) &&
    v.small_block_max_seconds <= 7200
  );
}
export async function readAutomation(signal: AbortSignal): Promise<AutomationState> {
  const data = await session.api.request<unknown>('/decision-automation', { signal });
  if (!record(data) || !validSettings(data.settings) || !Array.isArray(data.scenes) || !data.scenes.every(validScene))
    throw new Error('自动处置设置未完整返回。');
  return { settings: data.settings, scenes: data.scenes };
}
export function effectiveCeiling(value: AutomationSettings): AutomationLevel {
  return value.paused && (value.ceiling === 'conditional' || value.ceiling === 'full') ? 'approval' : value.ceiling;
}
export async function readMetrics(signal: AbortSignal): Promise<PlanMetrics> {
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  const data = await session.api.request<unknown>('/decision-plans/metrics?' + new URLSearchParams({ timezone }), {
    signal,
  });
  if (
    !record(data) ||
    typeof data.timezone !== 'string' ||
    !date(data.start) ||
    !date(data.end) ||
    Date.parse(data.end) <= Date.parse(data.start) ||
    !['triage_count', 'pending', 'executed', 'automatic', 'rejected', 'protected'].every(key => count(data[key])) ||
    (data.triage_mean_ms !== null && !count(data.triage_mean_ms)) ||
    Number(data.automatic) > Number(data.executed)
  )
    throw new Error('处置统计未完整返回。');
  return data as unknown as PlanMetrics;
}
function validSummary(v: unknown): v is DecisionPlanSummary {
  const texts = (value: unknown) =>
    Array.isArray(value) && value.length <= 8 && value.every(x => typeof x === 'string');
  return (
    record(v) &&
    validLevel(v.level) &&
    ['none', 'small', 'high'].includes(String(v.impact)) &&
    v.action === 'block_source' &&
    ['confirmed', 'undetermined', 'false_positive'].includes(String(v.verdict)) &&
    typeof v.confidence === 'number' &&
    v.confidence >= 0 &&
    v.confidence <= 1 &&
    date(v.confirm_until) &&
    texts(v.references) &&
    texts(v.missing) &&
    digest(v.evidence_sha256)
  );
}
export function planDeadline(run: ContinuousRecord) {
  return (
    run.plan?.confirm_until ??
    new Date(Math.min(Date.parse(run.created_at) + 15 * 60000, Date.parse(run.expires_at))).toISOString()
  );
}
export async function readPlans(cursor: string, limit: number, signal: AbortSignal): Promise<CursorPage<PlanRow>> {
  const user = session.current.value;
  const data = await session.api.request<unknown>(
    '/decision-plans?' + new URLSearchParams({ view: 'pending', cursor, limit: String(limit) }),
    { signal },
  );
  const valid = (v: unknown): v is PlanRow => {
    if (
      !user ||
      !record(v) ||
      v.state !== 'awaiting_confirmation' ||
      v.task_id !== '' ||
      v.task_state !== '' ||
      !record(v.run)
    )
      return false;
    const r = v.run;
    return (
      r.schema_version === 'decision-continuous.v1' &&
      r.tenant_id === user.tenant_id &&
      r.created_by === user.id &&
      r.state === 'awaiting_confirmation' &&
      policyID(r.id) &&
      policyID(r.evaluation_id) &&
      digest(r.sha256) &&
      policyID(r.event_id) &&
      policyID(r.policy_id) &&
      count(r.policy_revision) &&
      typeof r.target_ip === 'string' &&
      date(r.created_at) &&
      date(r.expires_at) &&
      (r.plan === undefined || validSummary(r.plan))
    );
  };
  if (
    !record(data) ||
    !Array.isArray(data.items) ||
    data.items.length > limit ||
    !data.items.every(valid) ||
    (data.next_cursor !== '' && !policyID(data.next_cursor))
  )
    throw new Error('待确认方案未完整返回。');
  return { items: data.items, next_cursor: data.next_cursor };
}
export async function readActivity(
  cursor: string,
  limit: number,
  signal: AbortSignal,
): Promise<CursorPage<PlanActivity>> {
  const data = await session.api.request<unknown>(
    '/decision-plans/activity?' + new URLSearchParams({ cursor, limit: String(limit) }),
    { signal },
  );
  const valid = (v: unknown): v is PlanActivity =>
    record(v) &&
    policyID(v.id) &&
    date(v.at) &&
    typeof v.kind === 'string' &&
    Object.hasOwn(activityKinds, v.kind) &&
    typeof v.state === 'string' &&
    typeof v.object === 'string' &&
    typeof v.code === 'string' &&
    (v.task_id === '' || policyID(v.task_id));
  if (
    !record(data) ||
    !Array.isArray(data.items) ||
    data.items.length > limit ||
    !data.items.every(valid) ||
    typeof data.next_cursor !== 'string' ||
    !/^[a-zA-Z0-9_-]{0,112}$/.test(data.next_cursor)
  )
    throw new Error('处置流水未完整返回。');
  return { items: data.items, next_cursor: data.next_cursor };
}
