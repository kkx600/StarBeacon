import { session } from '../../session';
import { draftStepNames, type DraftStep } from '../analysis/analysis';
import { validAssessment, type AlertAssessment } from '../alerts/assessment';
import type { TriageJob, TriageRequest } from '../alerts/triage';
import {
  eligibleDecisionResponse,
  type DecisionResponseRequest,
  type DecisionResponseRecord,
} from '../decisions/decisionResponses';
import { validEvaluation, type EvaluationRecord } from '../decisions/decisionEvaluations';
import type { GatewayRecord } from '../gateway/gatewayBlocks';

export const maxSteps = 16;
export type StepKind = DraftStep['kind'];
export const stepNames = { ...draftStepNames, protection: '保护名单检查', gateway: '网关阻断', compensate: '到期解除' };
export const issueNames: Record<string, string> = {
  model_binding: '请选择一个可用模型并填写置信度门槛。每条编排只使用一个研判步骤。',
  model_current: '模型配置已停用或修订已变化。',
  triage_required: '先添加 AI 研判，才能核对研判结论。',
  plugin_binding: '先添加 AI 研判，并选定人机协同策略、联动设备与生效时长。',
  plugin_current: '策略、模型修订或已登记设备与步骤配置不一致。',
  gateway_binding: '请选择经人工研判触发的网关策略。',
  gateway_current: '策略已停用、修订已变化、有效期已结束或启用了额外联动。',
  unbound_guard: '此步骤须与同一设备动作相邻。',
  action_guards: '动作前依次需要查保护名单和人工确认，动作后依次需要核验和到期解除。',
};
export const outcomeNames: Record<string, string> = {
  alert_verified: '原告警已核对',
  triage_observed: '已记录研判',
  triage_confirmed: '研判结论已核对',
  triage_failed: '研判未取得有效结果',
  below_threshold: '低于配置的置信度门槛',
  condition_met: '研判结论符合条件',
  condition_unmet: '研判结论不符合条件',
  protection_checked: '保护名单检查完成',
  protected: '命中保护名单',
  approved: '本步范围已确认',
  authorized: '已签发联动任务',
  requested: '已提交网关授权请求',
  authorization_denied: '原授权核对未通过',
  receipt_unknown: '设备回执无法核验',
  plugin_readback: '设备已回读租约',
  gateway_readback: '已回读网关规则',
  gateway_flow_paused: '出侧观察显示原连接已暂停',
  gateway_traffic_continued: '出侧仍有原连接流量',
  gateway_effect_unknown: '出侧效果待核对',
  expiry_recorded: '已记录租约解除期限',
  operator_notified: '已登记人工通知',
};
export interface Binding {
  id: string;
  revision: number;
}
export interface ModelBinding extends Binding {
  minimum_confidence: number;
}
export interface PluginBinding {
  policy: Binding;
  sensor_id: string;
  registration_id: string;
  connector_id: string;
  config_sha256: string;
  ttl_seconds: number;
}
export interface Step {
  kind: StepKind;
  name: string;
  description: string;
  minimum_severity?: string;
  model?: ModelBinding;
  plugin?: PluginBinding;
  gateway?: Binding;
}
export interface PlaybookDefinition {
  name: string;
  steps: Step[];
}
export interface Playbook {
  id: string;
  owner_id: string;
  revision: number;
  published_revision: number;
  published_sha256?: string;
  definition: PlaybookDefinition;
  sha256: string;
  updated_at: string;
}
export interface PlaybookIssue {
  step: number;
  code: string;
}
export interface Page<T> {
  items: T[];
  next_cursor: string;
}
export interface AlertIdentity {
  event_id: string;
  raw_sha256: string;
}
export interface StepResult {
  kind: StepKind;
  at: string;
  reference?: string;
  task_id?: string;
  outcome: string;
  lease_until?: string;
}
export interface PlaybookRun {
  id: string;
  playbook_id: string;
  revision: number;
  sha256: string;
  definition: PlaybookDefinition;
  alert: AlertIdentity & { source_ip: string; destination_ip: string; sensor_id: string };
  results: StepResult[];
  step_key?: string;
  state: 'running' | 'completed' | 'stopped';
  created_at: string;
}
export const runStates = { running: '进行中', completed: '已完成', stopped: '已停止' } as const;
export const isDigest = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const bindingValue = (b?: Binding) => (b ? b.id + '/' + b.revision : undefined);
export const deviceValue = (d?: {
  sensor_id: string;
  registration_id: string;
  connector_id: string;
  config_sha256: string;
}) => (d ? [d.sensor_id, d.registration_id, d.connector_id, d.config_sha256].join('/') : undefined);
export const errorText = (cause: unknown) =>
  cause instanceof Error ? cause.message : '编排请求暂未完成，请核对状态。';

export function newStep(kind: StepKind): Step {
  return { kind, name: stepNames[kind], description: '' };
}
export function newDefinition(): PlaybookDefinition {
  return { name: '', steps: [newStep('trigger')] };
}
export function actionSteps(kind: StepKind): Step[] {
  return (
    kind === 'plugin' || kind === 'gateway'
      ? (['protection', 'approval', kind, 'verify', 'compensate'] as const)
      : [kind]
  ).map(newStep);
}
export function adoptDraft(steps: DraftStep[]): Step[] {
  return steps.map(step => ({ ...newStep(step.kind), description: step.description }));
}
export function request<T>(path: string, method: 'POST' | 'PUT', input: unknown, key?: string, signal?: AbortSignal) {
  return session.api.request<T>(path, {
    method,
    headers: key ? { 'Idempotency-Key': key } : undefined,
    body: input,
    signal,
  });
}

export function beginTriage(run: PlaybookRun, model: ModelBinding, signal: AbortSignal) {
  const input: TriageRequest = {
    event_id: run.alert.event_id,
    raw_sha256: run.alert.raw_sha256,
    provider_id: model.id,
    provider_revision: model.revision,
    note: '编排人工研判',
    allow_context: true,
    manual_only: true,
  };
  return request<TriageJob>('/alerts/' + run.alert.event_id + '/triage', 'POST', input, run.step_key, signal);
}
export async function authorizePlugin(run: PlaybookRun, config: PluginBinding, signal: AbortSignal) {
  const triage = run.results.find(item => item.kind === 'triage');
  if (!triage?.reference || triage.outcome !== 'triage_confirmed' || !run.step_key)
    throw new Error('请先核对本次模型研判。');
  const key = 'pb_eval_' + run.id + '_' + run.results.length;
  const e = await request<EvaluationRecord>(
    '/decision-evaluations',
    'POST',
    { policy_id: config.policy.id, expected_revision: config.policy.revision, triage_id: triage.reference },
    key,
    signal,
  );
  const actor = session.current.value;
  if (
    !actor ||
    !(await validEvaluation(e, actor.tenant_id, actor.id)) ||
    e.result.event_id !== run.alert.event_id ||
    e.result.raw_sha256 !== run.alert.raw_sha256 ||
    !eligibleDecisionResponse(e)
  )
    throw new Error('原策略、告警材料或评估结论不满足处置确认条件。');
  const input: DecisionResponseRequest = {
    evaluation_sha256: e.sha256,
    sensor_id: config.sensor_id,
    registration_id: config.registration_id,
    connector_id: config.connector_id,
    config_sha256: config.config_sha256,
    ttl_seconds: config.ttl_seconds,
    reason: '操作员核对编排中的原告警与设备范围',
    confirmed: true,
  };
  return request<DecisionResponseRecord>(
    '/decision-evaluations/' + e.id + '/response',
    'POST',
    input,
    run.step_key,
    signal,
  );
}
export async function authorizeGateway(run: PlaybookRun, policy: Binding, signal: AbortSignal) {
  const root = '/alerts/' + run.alert.event_id;
  const a = await session.api.request<AlertAssessment>(root + '/assessment?sha256=' + run.alert.raw_sha256, { signal });
  if (
    !validAssessment(a) ||
    a.event_id !== run.alert.event_id ||
    a.raw_sha256 !== run.alert.raw_sha256 ||
    a.spec.verdict !== 'confirmed'
  )
    throw new Error('请先保存此告警的人工确认研判。');
  return request<GatewayRecord>(
    root + '/gateway-blocks',
    'POST',
    {
      policy_id: policy.id,
      policy_revision: policy.revision,
      assessment_revision: a.revision,
      raw_sha256: run.alert.raw_sha256,
    },
    run.step_key,
    signal,
  );
}
