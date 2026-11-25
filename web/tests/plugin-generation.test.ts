import { Checkbox, Select } from 'ant-design-vue';
import { DOMWrapper, flushPromises, mount } from '@vue/test-utils';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { effectScope, type ShallowRef } from 'vue';
import { createMemoryHistory, createRouter } from 'vue-router';
import { registerAnt } from '../packages/shared/src/ant';
import { ApiError } from '../packages/shared/src/api';
import type { Principal } from '../packages/shared/src/types';
import PluginEditor from '../platform/src/features/plugins/PluginEditor.vue';
import PluginGenerationDialog from '../platform/src/features/plugins/PluginGenerationDialog.vue';
import {
  usePluginGeneration,
  type GenerationJob,
  type GenerationRequest,
  type GeneratedPlugin,
} from '../platform/src/features/plugins/usePluginGeneration';
import { session } from '../platform/src/session';
import ResponsePluginsView from '../platform/src/views/ResponsePluginsView.vue';
import { button, click, deferred, principal } from './fixtures';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../platform/src/session', async () => ({
  session: { api: { request }, current: (await import('vue')).shallowRef(null) },
}));
const current = session.current as ShallowRef<Principal | null>;
const global = { plugins: [registerAnt] };
const endpoint = '/response-plugin-generation/jobs';
const provider = { id: 'model_fixture', revision: 3, name: '接口草稿模型', model: 'fixture-model', enabled: true };
const candidate: GeneratedPlugin = {
  name: '生成的健康检查',
  device: '防火墙',
  template: { schema_version: 'response.template.v1', health: { method: 'GET' } },
  examples: [{ method: 'GET', path: '/health', status: 200, response: '{"healthy":true}' }],
};
const job: GenerationJob = {
  id: 'plugin_gen_fixture',
  provider_id: provider.id,
  provider_revision: provider.revision,
  model: provider.model,
  device_type: 'firewall',
  abilities: ['health'],
  documentation_sha256: 'c'.repeat(64),
  prompt_version: 'response-plugin/1',
  state: 'succeeded',
  result: { state: 'succeeded', code: 'completed', usage: null },
  candidate,
  created_at: '2026-11-25T00:00:00Z',
  finished_at: '2026-11-25T00:01:00Z',
};
const input: GenerationRequest = {
  provider_id: provider.id,
  provider_revision: provider.revision,
  device_type: 'firewall',
  abilities: ['health'],
  documentation: 'GET /health 返回 healthy 布尔值。',
  allow_context: true,
};
const history = { items: [job], next_cursor: '', model_execution_available: true };
const queued: GenerationJob = {
  ...job,
  state: 'queued',
  candidate: undefined,
  result: { state: 'queued', code: 'awaiting_execution', usage: null },
};
const modelPage = { items: [provider, { ...provider, id: 'disabled_model', enabled: false }], available: true };
const modal = () => new DOMWrapper(document.querySelector<HTMLElement>('[role="dialog"]')!);

beforeEach(() => {
  request.mockReset();
  current.value = principal;
});

describe('AI 生成插件', () => {
  it('经用户许可提交选定模型和文档，随后进入生成记录', async () => {
    request.mockImplementation(async (url: string, options?: { method?: string }) => {
      if (url === '/models/providers') return modelPage;
      if (options?.method === 'POST' || url === endpoint + '/' + job.id) return queued;
      return history;
    });
    const view = mount(PluginGenerationDialog, { global, attachTo: document.body });
    await vi.waitFor(() =>
      expect(view.findAllComponents(Select)[0]?.props('options')).toEqual([
        { value: provider.id, label: provider.name + ' · ' + provider.model },
      ]),
    );
    expect(button('生成草稿').disabled).toBe(true);
    const providerField = view.findAllComponents(Select)[0]!;
    providerField.vm.$emit('update:value', provider.id);
    providerField.vm.$emit('change', provider.id);
    await modal().get('textarea[aria-label="设备接口文档"]').setValue(input.documentation);
    const consent = view.findAllComponents(Checkbox).find(control => control.text().includes('允许将本次接口文档'));
    expect(consent).toBeDefined();
    consent!.vm.$emit('update:checked', true);
    await flushPromises();
    expect(button('生成草稿').disabled).toBe(false);
    button('生成草稿').click();
    await vi.waitFor(() =>
      expect(request).toHaveBeenCalledWith(
        endpoint,
        expect.objectContaining({
          method: 'POST',
          body: input,
          headers: { 'Idempotency-Key': expect.any(String) },
        }),
      ),
    );
    await vi.waitFor(() => expect(modal().text()).toContain('排队中'));
    expect(modal().text()).toContain(job.documentation_sha256);
  });

  it('从生成记录查阅模型修订与摘要，交出待人工检查的草稿', async () => {
    request.mockImplementation(async (url: string) => {
      if (url === '/models/providers') return modelPage;
      if (url === endpoint) return history;
      return job;
    });
    const view = mount(PluginGenerationDialog, { global, attachTo: document.body });
    await click('生成记录');
    await vi.waitFor(() => expect(modal().text()).toContain('第 1 页 · 本页 1 条'));
    expect(modal().find('tbody code').text()).toBe(job.id);
    await click('查看');
    await vi.waitFor(() => expect(modal().text()).toContain(job.documentation_sha256));
    expect(modal().text()).toContain('修订 3');
    expect(modal().text()).toContain('声明式模板');
    await click('在编辑器审阅');
    expect(view.emitted('review')).toEqual([[candidate]]);
    expect(request.mock.calls.every(([, options]) => options.method !== 'POST')).toBe(true);
  });

  it('联动插件页交给普通草稿编辑器，保留用户填写编号和确认保存', async () => {
    request.mockResolvedValue({ items: [], next_after: '' });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/response/plugins', component: ResponsePluginsView }],
    });
    await router.push('/response/plugins');
    const view = mount(ResponsePluginsView, {
      global: { plugins: [registerAnt, router], stubs: { PluginGenerationDialog: true } },
      attachTo: document.body,
    });
    await click('AI生成插件');
    const ai = view.getComponent(PluginGenerationDialog);
    ai.vm.$emit('review', candidate);
    await flushPromises();
    const editor = view.getComponent(PluginEditor);
    expect(editor.props('generated')).toEqual(candidate);
    expect(editor.props('version')).toBeUndefined();
    expect(modal().get<HTMLInputElement>('[aria-label="编号"]').element.value).toBe('');
    expect(modal().get<HTMLInputElement>('[aria-label="插件名称"]').element.value).toBe(candidate.name);
    expect(modal().get<HTMLTextAreaElement>('[aria-label="模拟设备样例"]').element.value).toContain('/health');
    expect(request.mock.calls.every(([, options]) => options.method !== 'POST')).toBe(true);
  });
});

describe('生成记录读取与恢复', () => {
  it('未知提交复用原键，轮询已受理作业直到产生待审草稿', async () => {
    vi.useFakeTimers();
    const scope = effectScope();
    let reads = 0;
    request
      .mockImplementation(async (url: string, options?: { method?: string }) => {
        if (options?.method === 'POST') return queued;
        if (url === endpoint) return history;
        return reads++ ? job : queued;
      })
      .mockRejectedValueOnce(new ApiError(0, 'network_unavailable', '网络中断'));
    try {
      const runtime = scope.run(usePluginGeneration)!;
      expect(await runtime.submit(input)).toBe(false);
      expect(runtime.unresolved.value).toBe(true);
      const first = request.mock.lastCall![1];
      expect(await runtime.submit({ ...input, documentation: '另一份文档材料' })).toBe(false);
      expect(request).toHaveBeenCalledTimes(1);
      expect(await runtime.submit()).toBe(true);
      expect(request.mock.calls[1]![1].headers).toEqual(first.headers);
      expect(request.mock.calls[1]![1].body).toEqual(input);
      expect(runtime.unresolved.value).toBe(false);
      expect(runtime.selected.value?.state).toBe('queued');
      await vi.advanceTimersByTimeAsync(2000);
      expect(runtime.selected.value?.candidate).toEqual(candidate);
    } finally {
      scope.stop();
    }
  });

  it('资格拒绝后可以修正请求，并能翻页和中止旧结果读取', async () => {
    const scope = effectScope();
    const pending = deferred<GenerationJob>();
    try {
      const runtime = scope.run(usePluginGeneration)!;
      request.mockRejectedValueOnce(new ApiError(400, 'plugin_document_credentials', '文档包含凭据'));
      expect(await runtime.submit(input)).toBe(false);
      expect(runtime.unresolved.value).toBe(false);
      expect(runtime.submitError.value).toContain('包含凭据');
      expect(await runtime.submit()).toBe(false);
      request
        .mockResolvedValueOnce({ ...history, next_cursor: job.id })
        .mockResolvedValueOnce({ ...history, next_cursor: '' })
        .mockResolvedValueOnce(history);
      await runtime.loadHistory();
      runtime.move(true);
      await flushPromises();
      expect(request.mock.calls[2]![0]).toBe(endpoint + '?before=' + job.id);
      expect(runtime.cursors.value).toHaveLength(2);
      runtime.move(false);
      await flushPromises();
      expect(request.mock.calls[3]![0]).toBe(endpoint);
      request.mockResolvedValueOnce({ ...history, next_cursor: job.id }).mockResolvedValueOnce(history);
      runtime.resize(1, 50);
      await flushPromises();
      expect(request.mock.lastCall?.[0]).toBe(endpoint + '?limit=50');
      expect(runtime.cursors.value).toEqual(['']);
      runtime.move(true);
      await flushPromises();
      expect(request.mock.lastCall?.[0]).toBe(endpoint + '?before=' + job.id + '&limit=50');
      request.mockReturnValueOnce(pending.promise).mockRejectedValueOnce('记录不存在');
      const obsolete = runtime.inspect(job.id);
      const signal = request.mock.lastCall![1].signal;
      await runtime.inspect('new_selection');
      expect(signal.aborted).toBe(true);
      pending.resolve(job);
      await obsolete;
      expect(runtime.selected.value).toBeNull();
      expect(runtime.detailError.value).toBe('生成结果读取失败');
    } finally {
      scope.stop();
    }
  });
});
