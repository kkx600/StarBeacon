import { Button, Modal, Popconfirm, Select } from 'ant-design-vue';
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { effectScope, shallowRef, type ShallowRef } from 'vue';
import { createMemoryHistory, createRouter } from 'vue-router';
import { registerAnt } from '../packages/shared/src/ant';
import ListPager from '../packages/shared/src/components/ListPager.vue';
import {
  canSubmitPluginAction,
  pluginEntries,
  trialStages,
  type PluginAction,
  type PluginDeployment,
  type PluginOperation,
  type PluginOperationResult,
  type PluginOperations,
  type PluginVersion,
  type TrialStage,
} from '../packages/shared/src/responsePlugins';
import { formatTime, type Principal } from '../packages/shared/src/types';
import PluginEditor from '../platform/src/features/plugins/PluginEditor.vue';
import PluginOperationsPanel from '../platform/src/features/plugins/PluginOperationsPanel.vue';
import { usePluginOperations } from '../platform/src/features/plugins/usePluginOperations';
import { session } from '../platform/src/session';
import ResponsePluginsView from '../platform/src/views/ResponsePluginsView.vue';
import { button, click, deferred, principal, sensor } from './fixtures';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../platform/src/session', async () => ({
  session: { api: { request }, current: (await import('vue')).shallowRef(null) },
}));

const current = session.current as ShallowRef<Principal | null>;
const global = { plugins: [registerAnt] };
const plugin: PluginVersion = {
  id: 'fixture_edr',
  name: '受控联动设备',
  device: '实例设备',
  kind: 'template',
  state: 'draft',
  version: 2,
  template: { schema_version: 'response.template.v1', health: { method: 'GET' } },
  created_at: '2026-10-01T00:00:00Z',
  created_by: principal.id,
};
const binding = { plugin_id: plugin.id, device_id: 'device', binding_sha256: 'a'.repeat(64) };
const operationPath = '/response-plugins/' + plugin.id + '/operations';
const now = Date.now();
const time = (offset: number) => new Date(now + offset).toISOString();
const deployment: PluginDeployment = {
  plugin_id: plugin.id,
  sensor_id: sensor.id,
  sensor_name: sensor.name,
  generation: 4,
  version: 1,
  previous_version: 0,
  updated_at: time(-100_000),
  unavailable: false,
};
const enrolledSensor = { ...sensor, health: { ...sensor.health, plugin_bindings: [binding] } };

function receipt(action: TrialStage, offset: number): PluginOperationResult {
  return {
    task_id: 'task_' + action,
    action,
    version: plugin.version,
    state: 'succeeded',
    updated_at: time(offset),
    trial: {
      mode: 'read_only',
      binding,
      checks: ['health'],
      events: [{ entry: 'health', code: 'ok', duration_ms: 20, requests: [{ method: 'GET', status: 200 }] }],
    },
  };
}
const completeTrials = [receipt('capability', -1_000), receipt('read', -2_000), receipt('simulate', -3_000)];
const command = (action: PluginAction, version = plugin.version, generation = deployment.generation) => ({
  action,
  version,
  expected_generation: generation,
  sensor_id: sensor.id,
});

function modal() {
  const element = document.querySelector<HTMLElement>('[role="dialog"]');
  expect(element).not.toBeNull();
  return new DOMWrapper(element as HTMLElement);
}
function enter(label: string, value: string) {
  return modal()
    .get('[aria-label="' + label + '"]')
    .setValue(value);
}
function form(kind: 'template' | 'script') {
  const input = modal().get<HTMLInputElement>('input[type="radio"][value="' + kind + '"]');
  return input.setValue(true);
}

async function catalog(stubForms = false) {
  const path = '/response/plugins';
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path, component: ResponsePluginsView },
      { path: '/response/devices', component: { template: '<div />' } },
    ],
  });
  await router.push(path);
  const view = mount(ResponsePluginsView, {
    global: { plugins: [registerAnt, router], stubs: { PluginEditor: stubForms, PluginOperationsPanel: stubForms } },
    attachTo: document.body,
  });
  return { view, router };
}

function operationPanel(initial: PluginOperations) {
  let state = initial;
  request.mockImplementation(async (url: string, options?: { body?: PluginOperation }) => {
    if (url === '/sensors')
      return {
        items: [
          { ...enrolledSensor, id: 'offline_probe', status: 'offline' },
          { ...sensor, id: 'other_probe' },
          { ...enrolledSensor, id: 'archived_probe', active: false },
          enrolledSensor,
        ],
      };
    if (!options?.body) return state;
    const { action, version } = options.body;
    const trial = completeTrials.find(r => r.action === action);
    if (trial) state = { ...state, operations: [trial, ...state.operations] };
    else {
      const nextVersion = action === 'disable' ? 0 : version;
      state = {
        ...state,
        deployment: {
          ...state.deployment,
          version: nextVersion,
          previous_version: state.deployment.version,
          generation: state.deployment.generation + 1,
          unavailable: nextVersion > 0,
        },
        operations: [
          { task_id: action, action, version, state: 'succeeded', updated_at: time(10) },
          ...state.operations,
        ],
      };
    }
    return { task_id: action };
  });
  return mount(PluginOperationsPanel, { global, props: { version: plugin }, attachTo: document.body });
}

function expectPost(body: PluginOperation) {
  expect(request).toHaveBeenCalledWith(
    operationPath,
    expect.objectContaining({
      method: 'POST',
      body,
      headers: { 'Idempotency-Key': expect.any(String) },
    }),
  );
}

beforeEach(() => {
  current.value = principal;
  request.mockReset();
});

describe('联动插件工程页面', () => {
  it('输入校验后保存草稿，网络重试保留原提交键，编辑带上当前版本', async () => {
    const editor = mount(PluginEditor, { global, attachTo: document.body });
    await click('保存草稿');
    expect(modal().text()).toContain('请填写有效的编号');
    await enter('编号', plugin.id);
    await enter('插件名称', '  ' + plugin.name + '  ');
    await enter('适配设备', plugin.device);
    await enter('模拟设备样例', ' {');
    await click('保存草稿');
    expect(modal().text()).toContain('JSON 格式无效');
    await enter('模拟设备样例', '{}');
    await click('保存草稿');
    expect(modal().text()).toContain('设备样例须为 JSON 数组');
    await enter('模拟设备样例', '[]');
    await enter('模板 JSON', 'null');
    await click('保存草稿');
    expect(modal().text()).toContain('模板须使用 response.template.v1');
    expect(request).not.toHaveBeenCalled();
    await enter('模板 JSON', JSON.stringify(plugin.template));
    request.mockRejectedValueOnce(new Error('网络中断')).mockRejectedValueOnce(null).mockResolvedValueOnce(plugin);
    await click('保存草稿');
    expect(modal().text()).toContain('网络中断');
    await click('保存草稿');
    expect(modal().text()).toContain('插件草稿保存失败');
    await enter('插件名称', plugin.name);
    await click('保存草稿');
    expect(request.mock.calls).toHaveLength(3);
    const body = {
      id: plugin.id,
      name: plugin.name,
      device: plugin.device,
      expected_version: 0,
      examples: [],
      template: plugin.template,
    };
    const headers = request.mock.calls[0]![1].headers;
    expect(request).toHaveBeenLastCalledWith(
      '/response-plugins',
      expect.objectContaining({ method: 'POST', body, headers }),
    );
    expect(editor.emitted('saved')).toEqual([[plugin]]);
    editor.unmount();

    const edited = mount(PluginEditor, { global, props: { version: plugin }, attachTo: document.body });
    expect(modal().get('[aria-label="编号"]').attributes('disabled')).toBeDefined();
    await form('script');
    await enter('Starlark 源码', '');
    await click('保存草稿');
    expect(modal().text()).toContain('请填写 Starlark 源码并选择入口');
    await enter('Starlark 源码', 'def health(ctx): return True');
    const saving = deferred<PluginVersion>();
    request.mockReturnValueOnce(saving.promise);
    await click('保存草稿');
    edited.getComponent(Modal).vm.$emit('ok');
    await click('取消');
    expect(edited.emitted('close')).toBeUndefined();
    expect(request.mock.calls).toHaveLength(4);
    const options = request.mock.lastCall![1];
    expect(options.body).toEqual({
      id: plugin.id,
      name: plugin.name,
      device: plugin.device,
      expected_version: plugin.version,
      examples: [],
      script: { source: 'def health(ctx): return True', entries: ['health'] },
    });
    expect(options.headers).not.toEqual(headers);
    edited.unmount();
    expect(options.signal.aborted).toBe(true);
    saving.resolve(plugin);
    await flushPromises();
    expect(edited.emitted('saved')).toBeUndefined();
  });

  it('展示真实目录、设备状态和最近执行，支持续页和读取重试', async () => {
    const script: PluginVersion = {
      ...plugin,
      id: 'script',
      name: '设备脚本',
      kind: 'script',
      script: { source: 'source', entries: ['health', 'pull_alerts'] },
    };
    const stopped = { ...plugin, id: 'off', name: '已停用夹具' };
    const draft = {
      ...plugin,
      id: 'draft',
      name: '未试运行夹具',
      template: { ...plugin.template!, block: { method: 'POST' }, pull_alerts: {} },
    };
    request.mockRejectedValueOnce(new Error('目录离线')).mockImplementation(async (url: string) => {
      if (url === '/sensors') return { items: [] };
      if (url.includes('after=')) return { items: [stopped, draft], next_after: '' };
      return {
        items: [plugin, script, stopped, draft],
        next_after: 'start',
        deployments: [
          { ...deployment, unavailable: true },
          { ...deployment, plugin_id: script.id, sensor_name: '备用采集器' },
          { ...deployment, plugin_id: stopped.id, version: 0 },
        ],
        executions: [{ plugin_id: plugin.id, updated_at: time(-3000) }],
      };
    });
    const { view } = await catalog();
    await vi.waitFor(() => expect(view.text()).toContain('目录离线'));
    await click('重试');
    for (const expected of ['受控联动设备', '设备异常', '启用', '停用', '草稿', '拉取告警', formatTime(time(-3000))])
      expect(view.text()).toContain(expected);
    expect(view.get('h1').text()).toBe('联动插件');
    expect(view.get('[role="tab"][aria-selected="true"]').text()).toBe('联动插件');
    await click('下一页');
    expect(request.mock.lastCall![0]).toContain('after=start');
    expect(view.text()).toContain('第 2 页');
    await click('上一页');
    expect(request.mock.lastCall![0]).not.toContain('after=');
    view.getComponent(ListPager).vm.$emit('change', 1, 50);
    await flushPromises();
    expect(request.mock.lastCall![0]).toContain('limit=50');
  });

  it('目录将选中版本交给编辑和试运行入口，切换租户关闭旧窗口', async () => {
    request.mockResolvedValue({ items: [plugin], next_after: '' });
    const { view, router } = await catalog(true);
    await vi.waitFor(() => expect(view.text()).toContain(plugin.name));
    await click('编辑');
    const editing = view.getComponent(PluginEditor);
    expect(editing.props('version')).toEqual(plugin);
    editing.vm.$emit('close');
    await flushPromises();
    await click('新建插件');
    const create = view.getComponent(PluginEditor);
    expect(create.props('version')).toBeUndefined();
    const calls = request.mock.calls.length;
    create.vm.$emit('saved', { ...plugin, id: 'new_fixture' });
    await flushPromises();
    expect(view.findComponent(PluginEditor).exists()).toBe(false);
    expect(request).toHaveBeenCalledTimes(calls + 1);
    await click('试运行');
    expect(view.getComponent(PluginOperationsPanel).props('version')).toEqual(plugin);
    current.value = { ...principal, tenant_id: 'tenant_two' };
    await flushPromises();
    expect(view.findComponent(PluginOperationsPanel).exists()).toBe(false);
    await click('联动设备');
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/response/devices'));
  });

  it('同版本回执逐档解锁试运行和签名下发', async () => {
    operationPanel({ deployment, binding, operations: [] });
    const trialButtons = () => modal().findAll<HTMLButtonElement>('[aria-label="试运行"] button');
    await vi.waitFor(() => expect(trialButtons()[0]?.element.disabled).toBe(false));
    expect(request).toHaveBeenCalledWith(operationPath + '?sensor_id=' + sensor.id, expect.any(Object));
    expect(trialButtons()[1]!.element.disabled).toBe(true);
    expect(trialButtons()[2]!.element.disabled).toBe(true);
    expect(button('签名并下发').disabled).toBe(true);
    for (const [index, item] of trialStages.entries()) {
      await vi.waitFor(() => expect(trialButtons()[index]?.element.disabled).toBe(false));
      trialButtons()[index]!.element.click();
      await vi.waitFor(() => expectPost(command(item.key)));
    }
    await vi.waitFor(() => expect(button('签名并下发').disabled).toBe(false));
    expect(modal().text()).toContain('GET 200');
  });

  it('下发、回退和停用分别冻结对应版本和部署代次', async () => {
    const panel = operationPanel({ deployment, binding, operations: completeTrials });
    await vi.waitFor(() => expect(button('签名并下发').disabled).toBe(false));
    const confirm = async (label: string) => {
      const trigger = panel
        .findAllComponents(Popconfirm)
        .find(p => p.getComponent(Button).text().replace(/\s/g, '') === label);
      expect(trigger).toBeDefined();
      trigger!.vm.$emit('confirm');
      await flushPromises();
    };
    await confirm('签名并下发');
    expectPost(command('publish'));
    expect(modal().text()).toContain('设备异常，等待重试');
    expect(modal().text()).toContain('已完成');
    await confirm('回退');
    expectPost(command('rollback', 1, 5));
    await confirm('停用');
    expectPost(command('disable', 1, 6));
    expect(panel.emitted('changed')?.length).toBeGreaterThanOrEqual(3);
    expect(button('停用').disabled).toBe(true);
  });

  it('读取回执失败暂停操作，刷新后恢复', async () => {
    const panel = operationPanel({ deployment, binding, operations: completeTrials });
    await vi.waitFor(() => expect(button('签名并下发').disabled).toBe(false));
    request.mockRejectedValueOnce(new Error('回执链接中断'));
    await click('刷新回执', modal().element);
    await vi.waitFor(() => expect(modal().text()).toContain('回执链接中断'));
    expect(button('签名并下发').disabled).toBe(true);
    await click('刷新回执', modal().element);
    await vi.waitFor(() => expect(button('签名并下发').disabled).toBe(false));
    panel.getComponent(Modal).vm.$emit('cancel');
    expect(panel.emitted('close')).toHaveLength(1);
  });

  it.each([
    [['health', 'block', 'verify', 'unblock'], '保留 IP 完成封禁'],
    [['health', 'isolate', 'verify', 'release'], '登记的测试终端完成隔离'],
    [['health', 'block', 'verify', 'unblock', 'isolate', 'release'], '保留 IP 与登记测试终端'],
  ] as const)('变更能力显示对应的本地试运行范围 %s', async (entries, description) => {
    const version: PluginVersion = {
      ...plugin,
      kind: 'script',
      template: undefined,
      script: { source: 'source', entries: [...entries] },
    };
    request
      .mockRejectedValueOnce(new Error('采集器不可达'))
      .mockImplementation(async (url: string) =>
        url === '/sensors'
          ? { items: [{ ...enrolledSensor, status: 'offline' }] }
          : { deployment, binding, operations: completeTrials.slice(1) },
      );
    const panel = mount(PluginOperationsPanel, { global, props: { version }, attachTo: document.body });
    await vi.waitFor(() => expect(modal().text()).toContain('采集器不可达'));
    expect(modal().text()).toContain(description);
    await click('重试', modal().element);
    await vi.waitFor(() =>
      expect(panel.getComponent(Select).props('options')).toEqual([
        { value: sensor.id, label: sensor.name + ' · 离线' },
      ]),
    );
    const trial = panel.findAllComponents(Popconfirm).find(p => p.getComponent(Button).text() === '试运行')!;
    await vi.waitFor(() => expect(trial.getComponent(Button).props('disabled')).toBe(false));
    trial.vm.$emit('confirm');
    await flushPromises();
    expect(request).toHaveBeenCalledWith(operationPath, expect.objectContaining({ body: command('capability') }));
  });
});

describe('联动试运行资格与重试', () => {
  it('以当前版本、有效期、顺序和绑定判定是否可发布，允许回退已签版本', () => {
    const state: PluginOperations = { deployment, binding, operations: completeTrials };
    expect(pluginEntries({ ...plugin, template: undefined })).toEqual([]);
    expect(canSubmitPluginAction('simulate', plugin.version, state)).toBe(true);
    expect(canSubmitPluginAction('publish', plugin.version, state)).toBe(true);
    expect(canSubmitPluginAction('publish', 1, state)).toBe(false);
    expect(canSubmitPluginAction('publish', 3, state)).toBe(false);
    expect(canSubmitPluginAction('simulate', 1, null)).toBe(false);
    expect(canSubmitPluginAction('rollback', 3, state)).toBe(false);
    expect(canSubmitPluginAction('rollback', 3, { ...state, deployment: { ...deployment, previous_version: 1 } })).toBe(
      true,
    );
    for (const change of [
      { state: 'running' },
      { state: 'failed' },
      { updated_at: time(-86_401_000) },
      { updated_at: time(-4_000) },
      { updated_at: 'invalid' },
      { trial: undefined },
      { trial: { ...completeTrials[0]?.trial, binding: { ...binding, binding_sha256: 'b'.repeat(64) } } },
    ]) {
      const operations = [{ ...completeTrials[0]!, ...change } as PluginOperationResult, ...completeTrials.slice(1)];
      expect(canSubmitPluginAction('publish', plugin.version, { ...state, operations })).toBe(false);
    }
  });

  it('未知提交复用幂等键，轮询进行中的任务，切换采集器取消旧请求', async () => {
    vi.useFakeTimers();
    const probe = shallowRef('');
    const scope = effectScope();
    const state: PluginOperations = { deployment, binding, operations: [] };
    const old = deferred<PluginOperations>();
    try {
      const runtime = scope.run(() => usePluginOperations(shallowRef(plugin), probe))!;
      expect(request).not.toHaveBeenCalled();
      await runtime.submit('simulate');
      request.mockRejectedValueOnce('回执错误').mockResolvedValueOnce(state);
      probe.value = sensor.id;
      await flushPromises();
      expect(runtime.error.value).toBe('试运行回执读取失败');
      await runtime.refresh();
      request.mockRejectedValueOnce('提交错误').mockRejectedValueOnce(new Error('提交状态未知'));
      await runtime.submit('simulate');
      expect(runtime.writeError.value).toBe('操作提交失败');
      const firstHeaders = request.mock.lastCall![1].headers;
      await runtime.submit('simulate');
      expect(runtime.writeError.value).toBe('提交状态未知');
      expect(request.mock.lastCall![1].headers).toEqual(firstHeaders);

      request
        .mockResolvedValueOnce({ task_id: 'queued' })
        .mockResolvedValueOnce({ ...state, operations: [{ ...completeTrials[2], state: 'queued' }] })
        .mockResolvedValueOnce({ ...state, operations: [completeTrials[2]] });
      await runtime.submit('simulate');
      expect(runtime.can('read')).toBe(false);
      await vi.advanceTimersByTimeAsync(2000);
      expect(runtime.can('read')).toBe(true);
      request.mockReturnValueOnce(old.promise);
      const writing = runtime.submit('read');
      const pending = request.mock.lastCall![1];
      expect(pending.headers).not.toEqual(firstHeaders);
      request.mockResolvedValueOnce(state);
      probe.value = 'alternate';
      await flushPromises();
      expect(pending.signal.aborted).toBe(true);
      old.reject(new Error('旧的采集器请求'));
      await writing;
      expect(runtime.writeError.value).toBe('');
      expect(request.mock.lastCall![0]).toContain('sensor_id=alternate');
    } finally {
      scope.stop();
    }
  });
});
