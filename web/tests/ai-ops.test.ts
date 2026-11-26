import { randomUUID, webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils';
import { shallowRef } from 'vue';
import { createMemoryHistory, createRouter } from 'vue-router';
import { Select, message } from 'ant-design-vue';
import { registerAnt } from '../packages/shared/src/ant';
import { ApiError } from '../packages/shared/src/api';
import { goJSONDigest } from '../packages/shared/src/utils/goJSONDigest';
import { click, closedMessage, principal } from './fixtures';
import { analysisOverview, analysisProvider, chatJob } from './analysisFixtures';
import { triageDigest, triageEvent, triageJob, triagePage } from './triageFixtures';
import { naturalAlertQuery } from '../platform/src/features/copilot/search';
import CopilotDrawer from '../platform/src/features/copilot/CopilotDrawer.vue';
import CopilotAnalysis from '../platform/src/features/copilot/CopilotAnalysis.vue';
import CopilotAlertTriage from '../platform/src/features/copilot/CopilotAlertTriage.vue';
import AutomationSettings from '../platform/src/features/settings/AutomationSettings.vue';
import DecisionPolicyForm from '../platform/src/features/decisions/DecisionPolicyForm.vue';
import {
  orderedPolicy,
  type PolicyChange,
  type PolicyRecord,
} from '../platform/src/features/decisions/decisionPolicies';
import { readActivity, readAutomation, readMetrics, readPlans } from '../platform/src/features/decisions/automation';
import AiOpsView from '../platform/src/views/AiOpsView.vue';
import App from '../platform/src/App.vue';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
const current = shallowRef({ ...principal });
vi.mock('../platform/src/session', () => ({
  session: {
    api: { request },
    get current() {
      return current;
    },
  },
}));
const settings = { revision: 2, ceiling: 'full', paused: false };
const metrics = {
  timezone: 'UTC',
  start: '2026-11-26T00:00:00Z',
  end: '2026-11-27T00:00:00Z',
  triage_count: 18,
  triage_mean_ms: 2450,
  pending: 0,
  executed: 3,
  automatic: 2,
  rejected: 1,
  protected: 4,
};
async function routerFor(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      {
        path: '/ai/ai-ops',
        component: AiOpsView,
        meta: { title: 'AI 值守', navWorkspace: 'ai-ops', navGroup: 'ai', admin: true },
      },
      { path: '/main', component: { template: '<h1>同租户页面</h1>' }, meta: { title: '同租户页面' } },
      { path: '/ai/assistant', component: { template: '<h1>智能对话</h1>' } },
      { path: '/sensors/tasks', component: { template: '<h1>任务记录</h1>' } },
      { path: '/system/settings', component: { template: '<h1>系统设置</h1>' } },
      { path: '/response/policies', component: { template: '<h1>决策策略</h1>' } },
      { path: '/alerts/list', component: { template: '<h1>告警列表</h1>' } },
    ],
  });
  await router.push(path);
  return router;
}
beforeEach(() => {
  current.value = { ...principal };
  request.mockReset();
  vi.stubGlobal('crypto', { subtle: webcrypto.subtle, randomUUID });
  vi.spyOn(message, 'success').mockImplementation(closedMessage);
});
describe('AI 值守和全局助手', () => {
  it('绑定实际指标、暂停回执与同一列表的处置流水', async () => {
    let saved = settings;
    request.mockImplementation(async (path: string) => {
      if (path === '/decision-automation') return { settings: saved, scenes: [] };
      if (path === '/decision-automation/pause') return (saved = { ...settings, revision: 3, paused: true });
      if (path.startsWith('/decision-plans/metrics?')) return metrics;
      if (path.startsWith('/decision-plans/activity?'))
        return {
          items: [
            {
              id: 'task_owned',
              at: metrics.start,
              kind: 'release',
              state: 'revoked',
              object: '192.0.2.12',
              code: '',
              task_id: 'task_owned',
            },
          ],
          next_cursor: '',
        };
      if (path.startsWith('/decision-plans?')) return { items: [], next_cursor: '' };
      throw new Error(path);
    });
    const router = await routerFor('/ai/ai-ops');
    const wrapper = mount(AiOpsView, { global: { plugins: [registerAnt, router] } });
    await flushPromises();
    expect(wrapper.text()).toContain('平均 2.45 秒');
    expect(wrapper.text()).toContain('自动执行 2');
    expect(wrapper.text()).toContain('没有待确认的方案');
    expect(wrapper.get('a[href*="section=automation"]').text()).toBe('自动处置设置');
    await wrapper
      .findAll('button')
      .find(button => button.text() === '暂停自动处置')!
      .trigger('click');
    await flushPromises();
    expect(request).toHaveBeenCalledWith('/decision-automation/pause', {
      method: 'POST',
      signal: expect.any(AbortSignal),
    });
    expect(wrapper.text()).toContain('人机协同');
    await wrapper
      .findAll('button')
      .find(button => button.text() === '查看处置流水')!
      .trigger('click');
    await flushPromises();
    expect(wrapper.findAll('table')).toHaveLength(1);
    expect(wrapper.text()).toContain('设备解除回读');
    expect(wrapper.text()).toContain('已解除');
  });

  it('查看者在当前页打开助手，只检索授权数据且切换账号即清空抽屉', async () => {
    current.value = { ...principal, role: 'viewer' };
    request.mockResolvedValue({ items: [], total: 7, page: 1, page_size: 10 });
    const router = await routerFor('/main');
    const wrapper = mount(App, { attachTo: document.body, global: { plugins: [registerAnt, router] } });
    try {
      await wrapper.get('.copilot-entry').trigger('click');
      await vi.waitFor(() => expect(document.querySelector('.ant-drawer-content')).toBeTruthy());
      const drawer = new DOMWrapper(document.querySelector('.ant-drawer-content')!);
      expect(drawer.text()).toContain('同租户页面');
      expect(drawer.text()).not.toContain('生成联动插件');
      expect(drawer.text()).not.toContain('打开智能对话');
      expect(router.currentRoute.value.path).toBe('/main');
      await drawer.get('textarea').setValue('查询最近 12 小时的高危告警');
      await drawer.get('form').trigger('submit');
      await flushPromises();
      expect(drawer.text()).toContain('7 条匹配告警');
      expect(request.mock.calls.map(([path]) => path)).toEqual(['/alerts/search']);
      expect(request.mock.calls[0]?.[1].body).toMatchObject({ severity: 'high', keyword: '' });
      current.value = { ...current.value, id: 'viewer_second' };
      await vi.waitFor(() => expect(document.querySelector('.ant-drawer-content')).toBeNull());
    } finally {
      wrapper.unmount();
    }
  });

  it('自然语言时间和级别不会污染指名的规则关键字', () => {
    const now = new Date('2026-11-26T12:00:00Z');
    const query = naturalAlertQuery('检索近 2 天的中危告警 “高危扫描检测”', now);
    expect(query).toMatchObject({ start: '2026-11-24T12:00:00.000Z', severity: 'medium', keyword: '高危扫描检测' });
    expect(() => naturalAlertQuery('最近 32 天的告警', now)).toThrow('31 天');
    expect(() => naturalAlertQuery('查询高危或低危告警', now)).toThrow('一个告警级别');
  });

  it('管理员核对模型许可、原提交与真正的编排草稿', async () => {
    const response = {
      ...chatJob,
      template: 'playbook-draft.v1',
      request: { ...chatJob.request, purpose: 'playbook_draft', question: '告警入库后核对再通知值班组' },
      evidence: { ...chatJob.evidence, segments: [] },
      answer: {
        summary: '告警触发后通知',
        observations: [],
        recommendations: [],
        steps: [
          { kind: 'trigger', description: '告警进入平台' },
          { kind: 'notify', description: '通知值班组' },
        ],
      },
    };
    let attempted = false;
    request.mockImplementation(async (path: string, options: { method?: string } = {}) => {
      if (path === '/models/providers') return { items: [analysisProvider], available: true };
      if (path === '/analysis/jobs' && options.method === 'POST') {
        if (!attempted) {
          attempted = true;
          throw new ApiError(0, 'network_unavailable', '原请求结果未知');
        }
        return response;
      }
      if (path.startsWith('/analysis/threads/'))
        return { id: response.request.thread_id, title: response.request.question, jobs: [response], next_cursor: '' };
      return { items: [], next_cursor: '', model_execution_available: true };
    });
    const wrapper = mount(CopilotAnalysis, {
      props: { draft: true, context: 'AI 值守' },
      global: { plugins: [registerAnt] },
    });
    await flushPromises();
    wrapper.getComponent(Select).vm.$emit('update:value', analysisProvider.id);
    await wrapper.get('textarea').setValue(response.request.question);
    await wrapper.get('form').trigger('submit');
    expect(attempted).toBe(false);
    await wrapper.get('input[type=checkbox]').setValue(true);
    await wrapper.get('form').trigger('submit');
    await flushPromises();
    expect(wrapper.text()).toContain('核对原提交');
    await wrapper.get('form').trigger('submit');
    await flushPromises();
    const sends = request.mock.calls.filter(
      ([path, options]) => path === '/analysis/jobs' && options.method === 'POST',
    );
    expect(sends).toHaveLength(2);
    expect(sends[0]?.[1].body).toMatchObject({
      question: response.request.question,
      purpose: 'playbook_draft',
      thread_id: '',
      allow_context: true,
    });
    expect(sends[0]?.[1].headers).toEqual(sends[1]?.[1].headers);
    expect(wrapper.text()).toContain('告警触发后通知');
    expect(wrapper.text()).toContain('通知值班组');
    expect(sends.every(([path]) => path === '/analysis/jobs')).toBe(true);
  });

  it('告警研判提交固定观测标记并显示原事实，抽屉的处置入口保持只读', async () => {
    request.mockImplementation(async (path: string, options: { body?: object; method?: string } = {}) =>
      path === '/models/providers'
        ? { items: [analysisProvider], available: true }
        : options.method === 'POST'
          ? { ...triageJob, request: options.body }
          : triagePage,
    );
    const wrapper = mount(CopilotAlertTriage, {
      props: { alert: { eventID: triageEvent, digest: triageDigest, title: '测试告警' } },
      global: { plugins: [registerAnt] },
    });
    await flushPromises();
    wrapper.getComponent(Select).vm.$emit('update:value', analysisProvider.id);
    await wrapper.get('input[type=checkbox]').setValue(true);
    await wrapper.get('form').trigger('submit');
    await flushPromises();
    expect(request).toHaveBeenCalledWith(
      '/alerts/' + triageEvent + '/triage?sha256=' + triageDigest,
      expect.objectContaining({
        method: 'POST',
        body: expect.objectContaining({ observation_only: true, raw_sha256: triageDigest }),
      }),
    );
    expect(wrapper.text()).toContain('观察到攻击尝试');
    expect(wrapper.text()).toContain('/owned-validation');
    expect(wrapper.findAll('button').map(button => button.text())).toEqual(['开始研判']);
  });

  it('普通统计问答带入当前页面名称并保留服务端事实引用', async () => {
    request.mockImplementation(async (path: string, options: { method?: string } = {}) => {
      if (path === '/models/providers') return { items: [analysisProvider], available: true };
      if (path === '/analysis/jobs' && options.method === 'POST') return chatJob;
      if (path.startsWith('/analysis/threads/'))
        return { id: chatJob.request.thread_id, title: '统计问答', jobs: [chatJob], next_cursor: '' };
      return { items: [], next_cursor: '', model_execution_available: true };
    });
    const wrapper = mount(CopilotAnalysis, {
      props: { draft: false, context: '流量分析', question: '哪些告警需要核对' },
      global: { plugins: [registerAnt] },
    });
    await flushPromises();
    wrapper.getComponent(Select).vm.$emit('update:value', analysisProvider.id);
    await wrapper.get('input[type=checkbox]').setValue(true);
    await wrapper.get('form').trigger('submit');
    await flushPromises();
    expect(wrapper.text()).toContain('alerts.total');
    expect(request).toHaveBeenCalledWith(
      '/analysis/jobs',
      expect.objectContaining({
        method: 'POST',
        body: expect.objectContaining({ question: '当前页面为「流量分析」。哪些告警需要核对', allow_context: true }),
      }),
    );
  });

  it('解释以当前总览筛选和真实处置指标为准，并能打开只生成草稿的插件入口', async () => {
    const router = await routerFor('/main');
    request.mockImplementation(async (path: string) => {
      if (path.startsWith('/decision-plans/metrics?')) return metrics;
      if (path === '/models/providers') return { items: [], available: false };
      return { items: [], next_cursor: '', execution_available: false };
    });
    const wrapper = mount(CopilotDrawer, {
      props: { context: '态势总览', workspace: 'overview', overview: analysisOverview, chatPath: '/ai/assistant' },
      attachTo: document.body,
      global: { plugins: [registerAnt, router] },
    });
    try {
      await flushPromises();
      const drawer = new DOMWrapper(document.querySelector('.ant-drawer-content')!);
      await click('解释本页数据');
      expect(drawer.text()).toContain('页面所选时段已索引告警 2 条');
      expect(request).not.toHaveBeenCalled();
      await wrapper.setProps({ context: 'AI 值守', workspace: 'ai-ops', overview: undefined });
      await click('解释本页数据');
      await flushPromises();
      expect(drawer.text()).toContain('已完成研判 18 条');
      await click('研判当前告警');
      expect(drawer.get('a[href="/alerts/list"]').text()).toBe('打开告警列表');
      await click('生成联动插件');
      await flushPromises();
      expect(document.querySelector('.ant-modal-title')?.textContent).toBe('AI 生成插件');
      expect(request.mock.calls.some(([path]) => path === '/response-plugin-generation/jobs')).toBe(true);
      expect(drawer.get('a[href="/ai/assistant"]').text()).toBe('打开智能对话');
    } finally {
      wrapper.unmount();
    }
  });

  it('系统设置用当前版本恢复全局上限并打开原场景修订', async () => {
    const record: PolicyRecord = {
      id: 'policy_owned',
      tenant_id: principal.tenant_id,
      created_by: principal.id,
      revision: 3,
      active: true,
      name: '测试场景',
      description: '',
      created_at: '2026-11-26T00:00:00Z',
      expires_at: '2027-01-26T00:00:00Z',
      definition_sha256: '',
      definition: {
        schema_version: 'decision-policy.v1',
        mode: 'approval',
        expression: 'confidence >= threshold',
        threshold: 0.8,
        candidate_action: 'block_source',
        max_age_seconds: 3600,
        protected_prefixes: [],
        continuous: { provider_id: analysisProvider.id, provider_revision: analysisProvider.revision },
      },
    };
    record.definition_sha256 = await goJSONDigest(orderedPolicy(record.definition));
    let saved = { ...settings, paused: true };
    request.mockImplementation(async (path: string, options: { method?: string; body?: unknown } = {}) => {
      if (path === '/decision-automation' && options.method === 'PUT') {
        saved = { ...(options.body as typeof saved), revision: 3 };
        return saved;
      }
      if (path === '/decision-automation')
        return {
          settings: saved,
          scenes: [
            {
              id: record.id,
              name: record.name,
              revision: 3,
              active: true,
              level: 'approval',
              effective: 'approval',
              small_block_max_seconds: 7200,
            },
          ],
        };
      if (path.endsWith('/revisions/3')) return record;
      if (path === '/decision-policies' && options.method === 'POST') {
        const change = options.body as PolicyChange;
        return {
          ...record,
          revision: 4,
          definition: change.definition,
          definition_sha256: await goJSONDigest(orderedPolicy(change.definition)),
        };
      }
      if (path === '/models/providers') return { items: [analysisProvider], available: true };
      throw new Error(path);
    });
    const router = await routerFor('/system/settings');
    const wrapper = mount(AutomationSettings, { attachTo: document.body, global: { plugins: [registerAnt, router] } });
    try {
      await flushPromises();
      expect(wrapper.text()).toContain('测试场景');
      expect(wrapper.text()).toContain('7200 秒');
      await wrapper.get('input[type=checkbox]').setValue(false);
      await wrapper.get('form').trigger('submit');
      await flushPromises();
      expect(request).toHaveBeenCalledWith(
        '/decision-automation',
        expect.objectContaining({
          method: 'PUT',
          body: { expected_revision: 2, ceiling: 'full', paused: false },
        }),
      );
      await click('编辑');
      await vi.waitFor(() => expect(wrapper.findComponent(DecisionPolicyForm).exists()).toBe(true));
      expect(wrapper.getComponent(DecisionPolicyForm).props('record')).toEqual(record);
      expect(document.querySelector('.ant-modal')?.textContent).toContain('场景自动化级别');
      const chooser = wrapper
        .getComponent(DecisionPolicyForm)
        .findAllComponents(Select)
        .find(select => select.attributes('aria-label') === '场景自动化级别');
      expect(chooser).toBeDefined();
      chooser!.vm.$emit('update:value', 'observe');
      await new DOMWrapper(document.body).get('.ant-modal form').trigger('submit');
      await vi.waitFor(() => expect(wrapper.findComponent(DecisionPolicyForm).exists()).toBe(false));
      expect(request).toHaveBeenCalledWith(
        '/decision-policies',
        expect.objectContaining({
          method: 'POST',
          body: expect.objectContaining({
            id: record.id,
            expected_revision: 3,
            definition: { ...record.definition, automation_level: 'observe' },
          }),
        }),
      );
    } finally {
      wrapper.unmount();
    }
  });

  it('读取接口的结构错误不会变成零统计或可操作的方案', async () => {
    const signal = new AbortController().signal;
    for (const body of [
      { settings: { revision: 0, ceiling: 'observe', paused: false }, scenes: [{ id: 'bad/id' }] },
      { settings: { revision: 0, ceiling: 'invalid', paused: true }, scenes: [] },
    ]) {
      request.mockResolvedValueOnce(body);
      await expect(readAutomation(signal)).rejects.toThrow('未完整返回');
    }
    request.mockResolvedValueOnce({ ...metrics, automatic: metrics.executed + 1 });
    await expect(readMetrics(signal)).rejects.toThrow('未完整返回');
    request.mockResolvedValueOnce({
      items: [{ state: 'awaiting_confirmation', run: { created_by: 'foreign' } }],
      next_cursor: '',
    });
    await expect(readPlans('', 20, signal)).rejects.toThrow('未完整返回');
    request.mockResolvedValueOnce({ items: [], next_cursor: '非法游标' });
    await expect(readActivity('', 20, signal)).rejects.toThrow('未完整返回');
  });
});
