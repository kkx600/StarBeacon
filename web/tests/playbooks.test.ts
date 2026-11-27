import { randomUUID, webcrypto } from 'node:crypto';
import { nextTick, reactive, shallowRef } from 'vue';
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { createMemoryHistory, createRouter } from 'vue-router';
import { InputNumber, Select, message } from 'ant-design-vue';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registerAnt } from '../packages/shared/src/ant';
import type { DeviceQuery, ResponseDevice } from '../packages/shared/src/responseDevices';
import { button, click, closedMessage, principal } from './fixtures';
import { analysisProvider, chatJob } from './analysisFixtures';
import { responseEvaluation, responseInput, responseReceipt, responseSensor } from './decisionResponseFixtures';
import { triageJob } from './triageFixtures';
import PlaybooksView from '../platform/src/views/PlaybooksView.vue';
import PlaybookRunsView from '../platform/src/views/PlaybookRunsView.vue';
import PlaybookEditor from '../platform/src/features/playbooks/PlaybookEditor.vue';
import PlaybookRunDetails from '../platform/src/features/playbooks/PlaybookRunDetails.vue';
import CopilotAnalysis from '../platform/src/features/copilot/CopilotAnalysis.vue';
import {
  actionSteps,
  authorizeGateway,
  authorizePlugin,
  beginTriage,
  bindingValue,
  deviceValue,
  newDefinition,
  type Playbook,
  type PlaybookDefinition,
  type PlaybookRun,
  type StepKind,
} from '../platform/src/features/playbooks/playbooks';

const { api } = vi.hoisted(() => ({ api: vi.fn() }));
const current = shallowRef({ ...principal });
vi.mock('../platform/src/session', () => ({
  session: {
    api: { request: api },
    get current() {
      return current;
    },
  },
}));
const event = { event_id: 'a'.repeat(64), raw_sha256: 'b'.repeat(64) };
const id = 'pbr_' + '1'.repeat(32);
const rowID = 'pb_' + '2'.repeat(32);
const now = '2026-11-27T01:00:00Z';
const roots: VueWrapper[] = [];
const model = { id: analysisProvider.id, revision: analysisProvider.revision, minimum_confidence: 0.9 };
const gateway = { id: 'gateway_review', revision: 1 };
const policy = { id: 'policy_owned', revision: 1 };
const deviceSensor = responseSensor();
const connector = deviceSensor.health.response_connectors![0]!;
const device: ResponseDevice = {
  ...connector,
  sensor_id: deviceSensor.id,
  sensor_name: deviceSensor.name,
  registration_id: deviceSensor.registration_id,
  sensor_status: 'online',
  last_seen: connector.observed_at,
  host_observed_at: connector.observed_at,
  observation: 'fresh',
  task_supported: true,
};
const registration = {
  policy,
  sensor_id: device.sensor_id,
  registration_id: device.registration_id,
  connector_id: device.connector_id,
  config_sha256: device.config_sha256,
  ttl_seconds: 60,
};
function catalog(path: string) {
  if (path === '/models/providers') return { items: [analysisProvider], available: true };
  if (path.startsWith('/decision-policies?'))
    return {
      items: [
        {
          ...policy,
          name: '人工确认策略',
          active: true,
          definition: { mode: 'approval', candidate_action: 'block_source' },
        },
      ],
      next_cursor: '',
    };
  if (path.startsWith('/gateway-block/policies?'))
    return {
      items: [
        {
          ...gateway,
          definition: { enabled: true, name: '原网关策略', trigger: 'review', valid_until: '2099-01-01T00:00:00Z' },
        },
      ],
      next_cursor: '',
    };
  if (path.startsWith('/response-connectors?')) {
    const query = Object.fromEntries(
      [...new URL(path, 'http://stub.invalid').searchParams].map(([k, v]) => [k, k === 'limit' ? Number(v) : v]),
    ) as unknown as DeviceQuery;
    return { items: [device], next_cursor: '', query, observed_at: connector.observed_at };
  }
  return undefined;
}
function run(
  kind: StepKind,
  def: PlaybookDefinition = { name: '编排验收', steps: [...newDefinition().steps, ...actionSteps(kind)] },
): PlaybookRun {
  return {
    id,
    playbook_id: rowID,
    revision: 1,
    sha256: event.raw_sha256,
    definition: def,
    state: 'running',
    created_at: now,
    step_key: 'pb_step_' + id + '_1',
    alert: { ...event, source_ip: '192.0.2.10', destination_ip: '192.0.2.11', sensor_id: 'sensor_owned' },
    results: [{ kind: 'trigger', at: now, outcome: 'alert_verified', reference: event.event_id }],
  };
}
async function routerFor(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/response/playbooks', component: PlaybooksView },
      { path: '/response/playbook-runs', component: PlaybookRunsView },
      { path: '/response/actions', component: { template: '<div />' } },
      { path: '/response/gateway-blocks', component: { template: '<div />' } },
    ],
  });
  await router.push(path);
  return router;
}
function clicked(label: string, wrapper: VueWrapper) {
  return click(label, wrapper.element);
}
beforeEach(() => {
  current.value = { ...principal };
  api.mockReset();
  vi.stubGlobal('crypto', { subtle: webcrypto.subtle, randomUUID });
  vi.spyOn(message, 'success').mockImplementation(closedMessage);
});
afterEach(() => {
  for (const wrapper of roots.splice(0)) wrapper.unmount();
});

describe('受控编排工作台', () => {
  it('先校验后保存草稿，网络失败可核对原键，发布后从原告警启动', async () => {
    let saved: Playbook | undefined;
    let firstSave = true;
    let firstStart = true;
    api.mockImplementation(async (path: string, opt = {}) => {
      const input = opt as { method?: string; body?: { definition?: PlaybookDefinition } };
      if (path === '/playbooks?limit=100') return { items: [], next_cursor: '' };
      if (path === '/playbooks/validate') return { issues: [] };
      if (path === '/playbooks') {
        if (firstSave) {
          firstSave = false;
          throw new Error('保存回执待核对');
        }
        saved = {
          id: rowID,
          owner_id: principal.id,
          revision: 1,
          published_revision: 0,
          definition: JSON.parse(JSON.stringify(input.body!.definition)),
          sha256: event.raw_sha256,
          updated_at: now,
        };
        return saved;
      }
      if (path.endsWith('/publish')) return { ...saved!, published_revision: 1, published_sha256: event.raw_sha256 };
      if (path.endsWith('/runs')) {
        if (firstStart) {
          firstStart = false;
          throw new Error('启动回执待核对');
        }
        return run('notify', saved!.definition);
      }
      return catalog(path);
    });
    const router = await routerFor('/response/playbooks?event_id=' + event.event_id + '&sha256=' + event.raw_sha256);
    const w = mount(PlaybooksView, { attachTo: document.body, global: { plugins: [registerAnt, router] } });
    roots.push(w);
    await flushPromises();
    await w.get('#playbook-name').setValue('配置审查');
    await clicked('保存草稿', w);
    expect(w.text()).toContain('保存回执待核对');
    await clicked('保存草稿', w);
    const writes = api.mock.calls.filter(([path]) => path === '/playbooks');
    expect(writes[0]?.[1].headers).toEqual(writes[1]?.[1].headers);
    expect(writes[0]?.[1].body).toMatchObject({ expected_revision: 0, definition: { name: '配置审查' } });
    await clicked('演练路径', w);
    expect(document.body.textContent).toContain('此处预览步骤顺序');
    await new DOMWrapper(document.body).get('.ant-modal-close').trigger('click');
    await clicked('发布修订', w);
    expect(w.text()).toContain('修订 1 · 已发布');
    await clicked('从告警运行', w);
    expect((document.querySelector('#playbook-event') as HTMLInputElement).value).toBe(event.event_id);
    const dialog = new DOMWrapper(document.body);
    await dialog.get('#playbook-event').setValue('材料不全');
    await dialog.get('#playbook-sha').setValue('');
    expect(button('启动编排').disabled).toBe(true);
    await dialog.get('#playbook-event').setValue(event.event_id);
    await dialog.get('#playbook-sha').setValue(event.raw_sha256);
    await click('启动编排');
    expect(document.body.textContent).toContain('启动回执待核对');
    expect(router.currentRoute.value.path).toBe('/response/playbooks');
    await click('启动编排');
    const starts = api.mock.calls.filter(([path]) => path.endsWith('/runs'));
    expect(starts).toHaveLength(2);
    expect(starts[0]?.[1].headers).toEqual(starts[1]?.[1].headers);
    expect(api).toHaveBeenCalledWith(
      '/playbooks/' + rowID + '/runs',
      expect.objectContaining({ body: { ...event, revision: 1, sha256: event.raw_sha256 } }),
    );
    expect(router.currentRoute.value.query.run).toBe(id);
  });

  it('读取失败后可恢复，修改既有草稿后仍需重新通过发布校验', async () => {
    const draft = {
      id: rowID,
      owner_id: principal.id,
      revision: 1,
      published_revision: 0,
      definition: {
        name: '待校验编排',
        steps: [...newDefinition().steps, { kind: 'gateway', name: '网关阻断', description: '' }],
      },
      sha256: event.raw_sha256,
      updated_at: now,
    };
    let firstRead = true;
    api.mockImplementation(async (path: string, options) => {
      if (path === '/playbooks?limit=100') {
        if (firstRead) {
          firstRead = false;
          throw new Error('编排目录暂时不可用');
        }
        return { items: [draft], next_cursor: '' };
      }
      if (path === '/playbooks/validate') return { issues: [{ step: 1, code: 'action_guards' }] };
      if (path === '/playbooks/' + rowID) return { ...draft, revision: 2, definition: options.body.definition };
      return catalog(path);
    });
    const router = await routerFor('/response/playbooks');
    const w = mount(PlaybooksView, { global: { plugins: [registerAnt, router] } });
    roots.push(w);
    await flushPromises();
    expect(w.text()).toContain('编排目录暂时不可用');
    await clicked('重试', w);
    expect(w.text()).toContain('修订 1 · 草稿');
    await clicked('新建编排', w);
    expect(w.findAll('.flow-step')).toHaveLength(1);
    w.getComponent(Select).vm.$emit('update:value', rowID);
    await nextTick();
    expect(w.findAll('.flow-step')).toHaveLength(2);
    await w.get('#playbook-name').setValue('待核对的新修订');
    await clicked('保存草稿', w);
    expect(api).toHaveBeenCalledWith(
      '/playbooks/' + rowID,
      expect.objectContaining({ method: 'PUT', body: expect.objectContaining({ expected_revision: 1 }) }),
    );
    expect(w.text()).toContain('修订 2 · 草稿');
    await clicked('发布修订', w);
    expect(w.text()).toContain('第 2 步 动作前依次需要查保护名单和人工确认');
    expect(api.mock.calls.some(([path]) => path.endsWith('/publish'))).toBe(false);
  });

  it('使用真实模型协议草稿的返回类型，采纳前不提交编排修订', async () => {
    const draft = {
      ...chatJob,
      template: 'playbook-draft.v1',
      request: { ...chatJob.request, purpose: 'playbook_draft', question: '高危告警由值班员核对' },
      evidence: { ...chatJob.evidence, segments: [] },
      answer: {
        summary: '待核对的步骤',
        observations: [],
        recommendations: [],
        steps: [
          { kind: 'trigger', description: '高危告警触发' },
          { kind: 'gateway', description: '核对登记网关后确认' },
        ],
      },
    };
    api.mockImplementation(async (path: string) => {
      if (path === '/analysis/jobs') return draft;
      if (path.startsWith('/analysis/threads/'))
        return { id: draft.request.thread_id, title: draft.request.question, jobs: [draft], next_cursor: '' };
      return catalog(path) ?? { items: [], next_cursor: '', model_execution_available: true };
    });
    const router = await routerFor('/response/playbooks');
    const w = mount(PlaybooksView, { attachTo: document.body, global: { plugins: [registerAnt, router] } });
    roots.push(w);
    await flushPromises();
    await clicked('AI生成编排', w);
    const composer = w.getComponent(CopilotAnalysis);
    composer.getComponent(Select).vm.$emit('update:value', analysisProvider.id);
    await composer.get('textarea').setValue(draft.request.question);
    await composer.get('input[type=checkbox]').setValue(true);
    await composer.get('form').trigger('submit');
    await flushPromises();
    await click('采用草稿');
    expect(w.text()).toContain('网关阻断');
    expect(api.mock.calls.some(([path, opt]) => path === '/playbooks' && opt?.method === 'POST')).toBe(false);
  });

  it('配置三种新步骤，插入动作时分别生成保护闭环，可调整或删除步骤', async () => {
    const definition = reactive(newDefinition());
    api.mockImplementation(async (path: string) => catalog(path));
    const w = mount(PlaybookEditor, { props: { modelValue: definition }, global: { plugins: [registerAnt] } });
    roots.push(w);
    await flushPromises();
    w.findAllComponents(Select)[1]!.vm.$emit('update:value', 'high');
    await w.get('#playbook-step-name').setValue('高危告警');
    await w.get('#playbook-description').setValue('按严重级别筛选');
    expect(definition.steps[0]).toMatchObject({
      minimum_severity: 'high',
      name: '高危告警',
      description: '按严重级别筛选',
    });
    const add = async (kind: StepKind) => {
      w.findAllComponents(Select)[0]!.vm.$emit('update:value', kind);
      await nextTick();
      await clicked('添加步骤', w);
    };
    await add('triage');
    w.findAllComponents(Select)[1]!.vm.$emit('update:value', bindingValue(model));
    await flushPromises();
    expect(definition.steps[1]?.model).toEqual(model);
    await w.getComponent(InputNumber).setValue(0.95, 'value');
    expect(definition.steps[1]?.model?.minimum_confidence).toBe(0.95);
    await add('plugin');
    w.findAllComponents(Select)[1]!.vm.$emit('update:value', bindingValue(policy));
    await nextTick();
    w.findAllComponents(Select)[2]!.vm.$emit('update:value', deviceValue(device));
    await nextTick();
    expect(definition.steps[4]?.plugin).toEqual(registration);
    await w.getComponent(InputNumber).setValue(45, 'value');
    expect(definition.steps[4]?.plugin?.ttl_seconds).toBe(45);
    await add('gateway');
    w.findAllComponents(Select)[1]!.vm.$emit('update:value', bindingValue(gateway));
    await nextTick();
    expect(definition.steps[9]?.gateway).toEqual(gateway);
    await clicked('上移', w);
    expect(definition.steps[8]?.kind).toBe('gateway');
    await clicked('下移', w);
    expect(definition.steps[9]?.kind).toBe('gateway');
    await clicked('删除', w);
    expect(definition.steps.filter(s => s.kind === 'gateway')).toHaveLength(0);
  });
});

describe('编排运行使用原业务接口', () => {
  it('按已发布的原材料提交人工模型作业，核对回执后才推进', async () => {
    const r = run('triage');
    r.definition.steps[1]!.model = model;
    const updated = {
      ...r,
      state: 'completed',
      results: [...r.results, { kind: 'triage', at: now, outcome: 'triage_confirmed', reference: triageJob.id }],
    };
    api.mockImplementation(async (path: string) => (path.endsWith('/triage') ? triageJob : updated));
    const router = await routerFor('/response/playbook-runs');
    const w = mount(PlaybookRunDetails, { props: { run: r }, global: { plugins: [registerAnt, router] } });
    roots.push(w);
    expect(
      w
        .findAll('button')
        .find(button => button.text() === '发起研判')
        ?.attributes('disabled'),
    ).toBeDefined();
    await w.get('input[type=checkbox]').setValue(true);
    await clicked('发起研判', w);
    expect(w.text()).toContain('研判已受理');
    expect(api).toHaveBeenCalledWith(
      '/alerts/' + event.event_id + '/triage',
      expect.objectContaining({
        headers: { 'Idempotency-Key': r.step_key },
        body: expect.objectContaining({ ...event, manual_only: true, allow_context: true }),
      }),
    );
    await clicked('核对结果', w);
    expect(w.emitted('updated')?.[0]?.[0]).toEqual(updated);
  });

  it('人机协同原评估与网关人工研判的身份均在授权前核对', async () => {
    const evaluation = await responseEvaluation('approval');
    const p = run('plugin');
    p.alert = { ...p.alert, event_id: evaluation.result.event_id, raw_sha256: evaluation.result.raw_sha256 };
    const scope = { ...registration, ...responseInput(evaluation) };
    const signal = new AbortController().signal;
    await expect(authorizePlugin(p, scope, signal)).rejects.toThrow('本次模型研判');
    p.results.push({ kind: 'triage', at: now, outcome: 'triage_confirmed', reference: triageJob.id });
    const response = await responseReceipt(evaluation);
    api.mockImplementation(async (path: string) => (path === '/decision-evaluations' ? evaluation : response));
    await expect(authorizePlugin(p, scope, signal)).resolves.toBe(response);
    expect(api).toHaveBeenCalledWith(
      '/decision-evaluations/' + evaluation.id + '/response',
      expect.objectContaining({
        headers: { 'Idempotency-Key': p.step_key },
        body: expect.objectContaining({ confirmed: true, evaluation_sha256: evaluation.sha256 }),
      }),
    );
    api.mockResolvedValueOnce({ ...evaluation, sha256: '0'.repeat(64) });
    await expect(authorizePlugin(p, scope, signal)).rejects.toThrow('不满足处置确认条件');
    const g = run('gateway');
    const assessment = {
      ...event,
      revision: 2,
      basis: 'human',
      owner_id: principal.id,
      owner_name: '管理员',
      analyst_id: principal.id,
      analyst: '管理员',
      updated_at: now,
      expires_at: '2099-01-01T00:00:00Z',
      spec: {
        status: 'closed',
        verdict: 'confirmed',
        outcome: 'attempt',
        note: '核对实验告警',
        evidence: ['检测记录'],
      },
    };
    api
      .mockResolvedValueOnce({ ...assessment, event_id: 'foreign' })
      .mockResolvedValueOnce(assessment)
      .mockResolvedValueOnce({ id: 'gateway_receipt' });
    await expect(authorizeGateway(g, gateway, signal)).rejects.toThrow('人工确认研判');
    await expect(authorizeGateway(g, gateway, signal)).resolves.toEqual({ id: 'gateway_receipt' });
    expect(api).toHaveBeenCalledWith(
      '/alerts/' + event.event_id + '/gateway-blocks',
      expect.objectContaining({
        body: {
          policy_id: gateway.id,
          policy_revision: gateway.revision,
          assessment_revision: 2,
          raw_sha256: event.raw_sha256,
        },
      }),
    );
    await beginTriage(g, model, signal);
  });

  it('设备核验等待原任务回执，并显示原任务和租约期限', async () => {
    const r = run('plugin', {
      name: '核对原设备回执',
      steps: [...newDefinition().steps, { ...actionSteps('triage')[0]!, model }, ...actionSteps('plugin')],
    });
    const taskID = 'task_' + '2'.repeat(32);
    const receipt = { at: now, reference: 'decision_response_owned', task_id: taskID };
    r.results.push(
      { kind: 'triage', at: now, outcome: 'triage_confirmed', reference: triageJob.id },
      { kind: 'protection', at: now, outcome: 'protection_checked' },
      { kind: 'approval', at: now, outcome: 'approved', reference: principal.id },
      { kind: 'plugin', ...receipt, outcome: 'authorized' },
    );
    const verified: PlaybookRun = {
      ...r,
      results: [
        ...r.results,
        { kind: 'verify', ...receipt, outcome: 'plugin_readback', lease_until: '2026-11-27T01:01:00Z' },
      ],
    };
    api.mockRejectedValueOnce(new Error('当前步骤仍在等待设备回执')).mockResolvedValueOnce(verified);
    const router = await routerFor('/response/playbook-runs');
    const w = mount(PlaybookRunDetails, { props: { run: r }, global: { plugins: [registerAnt, router] } });
    roots.push(w);
    await clicked('核对结果', w);
    expect(w.text()).toContain('当前步骤仍在等待设备回执');
    expect(w.emitted('updated')).toBeUndefined();
    await clicked('核对结果', w);
    expect(w.emitted('updated')?.[0]?.[0]).toEqual(verified);
    await w.setProps({ run: verified });
    expect(w.get('a').attributes('href')).toBe('/response/actions?task=' + taskID);
    expect(w.text()).toContain('设备已回读租约');
    expect(w.text()).toContain('租约期限');
    expect(w.text()).toContain('实际解除状态可在原任务核对');
    for (const [path, options] of api.mock.calls) {
      expect(path).toBe('/playbook-runs/' + id + '/steps');
      expect(options.body).toEqual({ step: 5, confirmed: true });
    }
  });

  it('本人运行目录按游标翻页，保护失败后保持停止状态', async () => {
    const r = run('gateway');
    const older = { ...r, id: 'pbr_' + '3'.repeat(32), definition: { ...r.definition, name: '较早的运行' } };
    const stopped = {
      ...r,
      state: 'stopped',
      results: [...r.results, { kind: 'protection', at: now, outcome: 'protected' }],
    };
    api.mockImplementation(async (path: string) => {
      if (path.includes('cursor=page_2')) return { items: [older], next_cursor: '' };
      if (path.includes('?')) return { items: [r], next_cursor: 'page_2' };
      if (path.endsWith('/steps')) return stopped;
      return r;
    });
    const router = await routerFor('/response/playbook-runs');
    const w = mount(PlaybookRunsView, { global: { plugins: [registerAnt, router] } });
    roots.push(w);
    await flushPromises();
    await clicked('下一页', w);
    expect(w.text()).toContain('较早的运行');
    await clicked('上一页', w);
    expect(w.text()).not.toContain('较早的运行');
    await clicked('查看', w);
    expect(router.currentRoute.value.query.run).toBe(id);
    await clicked('检查保护名单', w);
    expect(w.text()).toContain('命中保护名单');
    expect(w.text()).toContain('已停止');
    await clicked('刷新', w);
    expect(api.mock.calls.filter(([path]) => path === '/playbook-runs/' + id).length).toBeGreaterThanOrEqual(2);
  });
});
