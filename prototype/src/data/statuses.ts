import { statusTerms } from '../../../web/packages/shared/src/terms.ts';
import {
  alertSeverityTones,
  alertWorkflowTones,
  sensorConnectionTones,
  sensorHealthTones,
  statusTone,
  taskStateTones,
  type StatusToneMap,
} from '../../../web/packages/shared/src/statusTones.ts';
import type { ColumnSpec, PageSpec } from '../models';

const byFamily: Record<string, string[]> = {
  alert: ['待研判', '研判中', '已关联事件', '误报'],
  assessment: ['待复核', '已完成', '证据不足', '排队中'],
  rule: ['启用', '待验证', '灰度中', '草稿', '停用'],
  action: ['已生效', '结果未知', '已撤销', '运行中', '待确认'],
  'application-rule': ['启用', '停用'],
  'decision-evaluation': ['策略命中', '策略未命中', '保护网段排除', '不参与决策', '策略命中'],
  decision: ['启用', '启用', '待验证', '启用', '停用'],
  model: ['已验证', '待验证', '未配置', '未配置', '已验证'],
  integrity: ['完整会话', '缺少握手', '单向观测', '完整会话', '字节缺口', '活动快照'],
  tls: ['不可解密', '不可解密', '授权明文', '证据不足'],
  channel: ['已验证', '已验证', '待验证', '已验证', '已验证'],
  device: ['在线', '在线', '结果未知', '已过期'],
  protocol: [
    '明文可见',
    '明文可见',
    '条件能力',
    '仅元数据',
    '明文可见',
    '部分支持',
    '仅元数据',
    '部分支持',
    '条件能力',
    '部分支持',
  ],
  pcap: ['已完成', '不完整', '运行中', '已完成', '已过期'],
  'packet-archive': ['已归档', '等待上传', '原件待核查', '已归档', '捕获中', '确认待回收'],
  retention: ['默认'],
  incident: ['处理中', '待处理', '待复核', '已关闭'],
  case: ['处理中', '待处理', '待复核', '已关闭'],
  delivery: ['已发送', '重试中', '已送达', '无回执', '失败'],
  sandbox: ['运行中', '已完成', '结果未知', '排队中', '已取消'],
  sensor: ['在线', '在线', '在线', '在线', '离线', '在线'],
  platform: ['正常', '正常', '正常', '正常', '需关注', '正常'],
  audit: ['成功', '成功', '成功', '成功', '拒绝', '成功'],
  'login-log': ['成功', '成功', 'MFA 失败', '成功', '凭据错误', '成功'],
  tenant: ['启用', '启用', '停用', '启用'],
  user: ['启用', '启用', '停用', '启用'],
  role: ['启用', '启用', '停用'],
  network: ['启用', '启用', '停用'],
  account: ['已配置', '默认', '待验证'],
  asset: ['在线', '在线', '待确认', '离线'],
  interface: ['已发现', '已发现', '待确认'],
  address: ['已发现', '历史记录', '待确认'],
  identity: ['已关联', '待复核', '证据不足'],
  session: ['已结束', '活动中', '不完整'],
  vulnerability: ['待处理', '处理中', '待复核', '已关闭'],
  remediation: ['待处理', '处理中', '待复核', '已关闭'],
  review: ['待复核', '已完成', '证据不足'],
  timeline: ['已记录', '已记录', '待复核'],
  ticket: ['排队中', '已完成', '重试中'],
  sample: ['排队中', '运行中', '已完成', '证据不足'],
  file: ['排队中', '运行中', '已完成', '证据不足'],
  static: ['排队中', '运行中', '已完成', '结果未知'],
  'file-report': ['待复核', '已完成', '证据不足'],
  hunt: ['草稿', '处理中', '已完成'],
  behavior: ['待复核', '已完成', '证据不足'],
  'behavior-model': ['待训练', '已评测', '待复核'],
  'playbook-run': ['待确认', '运行中', '已完成', '结果未知'],
  backup: ['已完成', '运行中', '待验证'],
  release: ['待验证', '灰度中', '已发布', '已回滚'],
  'intel-hit': ['待研判', '已完成', '证据不足'],
  indicator: ['有效', '待复核', '已过期'],
  'intel-life': ['有效', '待复核', '已过期'],
  metric: ['待验证', '待复核'],
  quality: ['正常', '需关注', '证据不足'],
  'data-quality': ['正常', '需关注', '证据不足'],
  'packet-time': ['正常', '无数据', '待复核'],
  log: ['已接收', '待复核'],
  risk: ['待复核', '已完成'],
  priority: ['待处理', '已分派'],
};

// 生命周期与运行模式分别建模；未知配置不套用任务完成或执行结果状态。
export function statusesFor(page: Pick<PageSpec, 'family' | 'actionMode'>): string[] {
  return (
    byFamily[page.family] ??
    (page.actionMode === 'task' ? ['排队中', '运行中', '已完成', '失败'] : ['启用', '待验证', '停用'])
  );
}
export function initialStatusFor(page: PageSpec): string {
  const initial: Record<string, string> = {
    action: '待确认',
    rule: '草稿',
    decision: '待验证',
    model: '未配置',
    channel: '待验证',
    device: '待验证',
    sensor: '未注册',
    tenant: '启用',
    user: '启用',
    case: '待处理',
    incident: '待处理',
    report: '待审核',
  };
  return initial[page.family] ?? (page.actionMode === 'task' ? '排队中' : '待验证');
}

// 原型沿用合成记录的状态键。色调从所属业务的表中读取，标签文字可以独立格式化。
export const severityTones = {
  严重: alertSeverityTones.critical,
  高危: alertSeverityTones.high,
  中危: alertSeverityTones.medium,
  低危: alertSeverityTones.low,
  未知: alertSeverityTones.unknown,
} as const satisfies StatusToneMap;

export const alertTones = {
  待研判: alertWorkflowTones.open,
  研判中: alertWorkflowTones.investigating,
  已关联事件: alertWorkflowTones.linked,
  误报: alertWorkflowTones.false_positive,
  已关闭: alertWorkflowTones.closed,
} as const satisfies StatusToneMap;

export const connectionTones = {
  在线: sensorConnectionTones.online,
  离线: sensorConnectionTones.offline,
  停用: sensorConnectionTones.disabled,
  未注册: 'neutral',
} as const satisfies StatusToneMap;

export const healthTones = {
  正常: sensorHealthTones.healthy,
  需关注: sensorHealthTones.degraded,
  异常: sensorHealthTones.abnormal,
  无数据: sensorHealthTones.missing,
  磁盘空间不足: sensorHealthTones.degraded,
  'CPU 占用高': sensorHealthTones.degraded,
  内存占用高: sensorHealthTones.degraded,
  丢包率高: sensorHealthTones.degraded,
  指标不全: sensorHealthTones.degraded,
} as const satisfies StatusToneMap;

export const taskTones = {
  排队中: taskStateTones.queued,
  等待执行回执: taskStateTones.queued,
  运行中: taskStateTones.running,
  重试中: taskStateTones.retrying,
  已完成: taskStateTones.succeeded,
  失败: taskStateTones.failed,
  结果未知: taskStateTones.unknown,
  已过期: taskStateTones.expired,
  已取消: taskStateTones.cancelled,
  原生执行未配置: 'warning',
  待验证: statusTerms.待验证,
  证据不足: statusTerms.证据不足,
  不完整: statusTerms.不完整,
} as const satisfies StatusToneMap;

export const configurationTones = {
  默认: 'neutral',
  草稿: statusTerms.草稿,
  启用: statusTerms.启用,
  停用: statusTerms.停用,
  未启用: statusTerms.未启用,
  未配置: statusTerms.未配置,
  待验证: statusTerms.待验证,
  已验证: statusTerms.已验证,
  验证失败: statusTerms.验证失败,
  灰度中: 'info',
  已发布: 'neutral',
  已回滚: 'neutral',
} as const satisfies StatusToneMap;

const reviewTones = {
  ...taskTones,
  待处理: statusTerms.待处理,
  处理中: statusTerms.处理中,
  待复核: statusTerms.待复核,
  已关闭: statusTerms.已关闭,
  待审核: 'warning',
  待训练: 'warning',
  待研判: alertWorkflowTones.open,
} as const satisfies StatusToneMap;

export const responseTones = {
  ...taskTones,
  待确认: statusTerms.待确认,
  已确认: statusTerms.已确认,
  已驳回: statusTerms.已驳回,
  已生效: statusTerms.已生效,
  已撤销: statusTerms.已撤销,
  未执行: statusTerms.未执行,
  待验证: statusTerms.待验证,
} as const satisfies StatusToneMap;

const integrityTones = {
  完整: 'success',
  完整会话: 'success',
  缺少握手: 'danger',
  单向观测: 'warning',
  字节缺口: 'danger',
  不完整: statusTerms.不完整,
  等待上传: 'warning',
  原件待核查: 'warning',
  确认待回收: 'warning',
  条件能力: 'warning',
  仅元数据: 'warning',
  部分支持: 'warning',
  支持: 'success',
  不支持: statusTerms.不支持,
  证据不足: statusTerms.证据不足,
} as const satisfies StatusToneMap;

const auditTones = { 成功: 'success', 拒绝: 'danger', 'MFA 失败': 'danger', 凭据错误: 'danger' } as const;
const deliveryTones = { ...taskTones, 已发送: 'success', 已送达: 'success', 无回执: 'neutral' } as const;
const inventoryTones = {
  ...connectionTones,
  待确认: statusTerms.待确认,
  待复核: statusTerms.待复核,
  证据不足: statusTerms.证据不足,
} as const;
const qualityTones = { ...healthTones, 证据不足: statusTerms.证据不足 } as const;
const familyTones = new Map<string, StatusToneMap>([
  ['alert', alertTones],
  ['sensor', connectionTones],
  ['platform', healthTones],
  ['quality', qualityTones],
  ['data-quality', qualityTones],
  ['packet-time', { ...healthTones, 待复核: statusTerms.待复核 }],
  ['action', responseTones],
  ['playbook-run', responseTones],
  ['device', { ...connectionTones, ...responseTones, ...configurationTones }],
  ['assessment', reviewTones],
  ['incident', reviewTones],
  ['case', reviewTones],
  ['review', reviewTones],
  ['timeline', reviewTones],
  ['vulnerability', reviewTones],
  ['remediation', reviewTones],
  ['risk', reviewTones],
  ['priority', reviewTones],
  ['hunt', { ...configurationTones, ...reviewTones }],
  ['intel-hit', reviewTones],
  ['indicator', reviewTones],
  ['intel-life', reviewTones],
  ['behavior', reviewTones],
  ['behavior-model', reviewTones],
  ['file-report', reviewTones],
  ['metric', reviewTones],
  ['log', reviewTones],
  ['task', taskTones],
  ['pcap', taskTones],
  ['sandbox', taskTones],
  ['sample', taskTones],
  ['file', taskTones],
  ['static', taskTones],
  ['ticket', taskTones],
  ['backup', taskTones],
  ['report', reviewTones],
  ['packet-archive', integrityTones],
  ['integrity', integrityTones],
  ['tls', integrityTones],
  ['protocol', integrityTones],
  ['session', integrityTones],
  ['delivery', deliveryTones],
  ['audit', auditTones],
  ['login-log', auditTones],
  ['asset', inventoryTones],
  ['interface', inventoryTones],
  ['address', inventoryTones],
  ['identity', inventoryTones],
]);

export function recordStatusTone(page: PageSpec, state: unknown, column?: ColumnSpec) {
  if (column?.kind === 'level') return statusTone(severityTones, state);
  if (page.family === 'sensor' && column?.key === 'health') return statusTone(healthTones, state);
  return statusTone(
    familyTones.get(page.family) ?? (page.actionMode === 'task' ? taskTones : configurationTones),
    state,
  );
}

export function evidenceStatusTone(page: PageSpec, state: unknown) {
  if (typeof state !== 'string') return 'neutral';
  if (Object.hasOwn(integrityTones, state)) return statusTone(integrityTones, state);
  if (Object.hasOwn(responseTones, state)) return statusTone(responseTones, state);
  return recordStatusTone(page, state);
}
