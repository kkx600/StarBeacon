export const entryLabels = {
  health: '健康检查',
  pull_alerts: '拉取告警',
  block: '封禁',
  verify: '核验',
  unblock: '解封',
  isolate: '隔离终端',
  release: '解除隔离',
} as const;
export type PluginEntry = keyof typeof entryLabels;
export type PluginKind = 'template' | 'script';

export const trialStages = [
  { key: 'simulate', label: '模拟设备' },
  { key: 'read', label: '真实设备只读' },
  { key: 'capability', label: '按能力验收' },
] as const;
export type TrialStage = (typeof trialStages)[number]['key'];
export type PluginAction = TrialStage | 'publish' | 'rollback' | 'disable';

export interface PluginBinding {
  plugin_id: string;
  device_id: string;
  binding_sha256: string;
}
export interface PluginScript {
  source: string;
  entries: PluginEntry[];
}
export interface PluginExample {
  method: string;
  path: string;
  query?: string;
  request?: string;
  status: number;
  response?: string;
}
export interface PluginTemplate {
  schema_version: string;
  health?: { method?: string };
  block?: { method?: string };
  pull_alerts?: object;
}
export interface PluginDraft {
  id: string;
  expected_version: number;
  name: string;
  device: string;
  template?: PluginTemplate;
  script?: PluginScript;
  examples?: PluginExample[];
}
export interface PluginVersion extends Omit<PluginDraft, 'expected_version'> {
  version: number;
  kind: PluginKind;
  state: 'draft' | 'superseded';
  template_sha256?: string;
  script_sha256?: string;
  created_at: string;
  created_by: string;
}
export interface PluginDeployment {
  plugin_id: string;
  sensor_id: string;
  sensor_name: string;
  generation: number;
  version: number;
  previous_version: number;
  updated_at: string;
  unavailable: boolean;
}
export interface PluginPage {
  items: PluginVersion[];
  next_after: string;
  deployments?: PluginDeployment[];
  executions?: { plugin_id: string; updated_at: string }[];
}
export interface PluginTrialResult {
  mode: 'read_only' | 'block' | 'isolate' | 'block_and_isolate';
  binding: PluginBinding;
  checks: string[];
  events: {
    entry: string;
    code: string;
    duration_ms: number;
    requests?: { method: string; status: number }[];
  }[];
}
export interface PluginOperationResult {
  task_id: string;
  action: PluginAction;
  version: number;
  state: 'queued' | 'delivered' | 'running' | 'succeeded' | 'failed' | 'unknown' | 'expired' | 'cancelled';
  code?: string;
  updated_at: string;
  trial?: PluginTrialResult;
}
export interface PluginOperations {
  deployment: PluginDeployment;
  binding?: PluginBinding;
  operations: PluginOperationResult[];
}
export interface PluginOperation {
  sensor_id: string;
  version: number;
  action: PluginAction;
  expected_generation: number;
}

export function pluginEntries(v: PluginVersion): PluginEntry[] {
  if (v.script) return v.script.entries;
  const result: PluginEntry[] = [];
  if (v.template?.health?.method) result.push('health');
  if (v.template?.pull_alerts) result.push('pull_alerts');
  if (v.template?.block?.method) result.push('block', 'verify', 'unblock');
  return result;
}

export function trialResult(state: PluginOperations | null, version: number, stage: TrialStage) {
  return state?.operations.find(op => op.version === version && op.action === stage);
}

export function isPendingPluginOperation(op: PluginOperationResult) {
  return ['queued', 'delivered', 'running'].includes(op.state);
}

export function canSubmitPluginAction(
  action: PluginAction,
  version: number,
  state: PluginOperations | null,
  now = Date.now(),
) {
  if (!state?.binding || state.operations.some(isPendingPluginOperation)) return false;
  if (action === 'rollback') return state.deployment.previous_version > 0;
  if (action === 'disable') return state.deployment.version > 0;
  const depth = action === 'publish' ? trialStages.length : trialStages.findIndex(s => s.key === action);
  if (depth < 0 || (action === 'publish' && state.deployment.version === version)) return false;
  let previous = 0;
  for (const stage of trialStages.slice(0, depth)) {
    const trial = trialResult(state, version, stage.key);
    const completed = trial ? Date.parse(trial.updated_at) : Number.NaN;
    if (
      trial?.state !== 'succeeded' ||
      trial.trial?.binding.binding_sha256 !== state.binding.binding_sha256 ||
      !Number.isFinite(completed) ||
      completed <= previous ||
      completed < now - 86_400_000
    )
      return false;
    previous = completed;
  }
  return true;
}

export const pluginOperationLabels: Record<PluginAction, string> = {
  simulate: '模拟设备',
  read: '真实设备只读',
  capability: '按能力验收',
  publish: '签名并下发',
  rollback: '回退',
  disable: '停用',
};
