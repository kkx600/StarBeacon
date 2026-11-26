import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DOMWrapper, flushPromises, mount, type VueWrapper } from '@vue/test-utils';
import { createMemoryHistory, createRouter } from 'vue-router';
import { registerAnt } from '../packages/shared/src/ant';
import ListPager from '../packages/shared/src/components/ListPager.vue';
import GatewayBlocksView from '../platform/src/views/GatewayBlocksView.vue';
import GatewayBlockSettings from '../platform/src/features/settings/GatewayBlockSettings.vue';
import GatewayPolicyEditor from '../platform/src/features/gateway/GatewayPolicyEditor.vue';
import {
  formatGatewayFlow,
  readGatewayDevices,
  readGatewayPolicies,
  readGatewayRecord,
  readGatewayRecords,
  readGatewaySettings,
  saveGatewayPolicy,
  saveGatewaySettings,
  type GatewayDefinition,
  type GatewayDevice,
  type GatewayPolicy,
  type GatewayRecords,
  type GatewayRecord,
} from '../platform/src/features/gateway/gatewayBlocks';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../platform/src/session', () => ({ session: { api: { request } } }));

const stamp = '2026-11-26T05:11:32.218Z';
const flow = {
  source_ip: '10.203.35.3',
  source_port: 42313,
  destination_ip: '10.203.36.3',
  destination_port: 8080,
  transport: 'tcp',
} as const;
const first: GatewayRecord = {
  id: 'gateway_paused',
  event_id: '0'.repeat(64),
  raw_sha256: 'e'.repeat(64),
  policy_id: 'policy_gateway',
  sensor_id: 'sensor_owned',
  registration_id: 'registration_owned',
  policy_revision: 1,
  assessment_revision: 3,
  trigger: 'review',
  state: 'authorized',
  code: '',
  flow,
  observed_at: stamp,
  created_at: stamp,
  task_id: 'task_gateway',
  task_state: 'succeeded',
  follow_up_state: 'issued',
  follow_up_code: 'policy_authorized',
  follow_up_task_id: 'task_fixture',
  follow_up_task_state: 'succeeded',
  gateway_result: {
    request_id: 'gateway_paused',
    verified_at: stamp,
    lease_until: stamp,
    observation: {
      state: 'paused',
      interface: 'eth1',
      code: '',
      started_at: stamp,
      finished_at: stamp,
      egress_packets: 3,
      original_packets: 0,
    },
  },
};
const continued = structuredClone(first);
continued.id = 'gateway_continued';
continued.gateway_result!.request_id = continued.id;
Object.assign(continued.gateway_result!.observation!, {
  state: 'continued',
  reconnect: { ...flow, source_port: 42400 },
});
Object.assign(continued, {
  trigger: 'rule',
  assessment_revision: undefined,
  follow_up_state: 'skipped',
  follow_up_code: 'traffic_continued',
  follow_up_task_id: undefined,
  follow_up_task_state: undefined,
});
const unknown = structuredClone(continued);
unknown.id = 'gateway_unknown';
unknown.gateway_result!.request_id = unknown.id;
Object.assign(unknown.gateway_result!.observation!, {
  state: 'unknown',
  code: 'window_short',
  reconnect: undefined,
  interface: '',
});
unknown.follow_up_code = 'observation_unavailable';
const denied: GatewayRecord = {
  ...continued,
  id: 'gateway_denied',
  state: 'denied',
  code: 'protected_endpoint',
  gateway_result: undefined,
  task_state: undefined,
  follow_up_state: 'none',
  follow_up_code: '',
};
const pending: GatewayRecord = {
  ...denied,
  id: 'gateway_pending',
  state: 'pending',
  code: '',
  follow_up_state: 'pending',
};
const waiting: GatewayRecord = { ...pending, id: 'gateway_wait', state: 'authorized', task_state: 'running' };
const old: GatewayRecord = { ...waiting, id: 'gateway_old', task_state: undefined };
const all = [first, continued, unknown, denied, pending, waiting, old];
const totals = { total: 7, paused: 1, continued: 1, unknown: 1, protected: 1 };
const records: GatewayRecords = {
  items: all,
  enabled: true,
  online_gateways: 1,
  last_day: totals,
  next_cursor: old.id,
};

const settings = { enabled: false, per_minute: 10, revision: 0 };
const device: GatewayDevice = {
  plugin_id: 'plugin_owned',
  connector_id: 'connector_owned',
  device_id: 'device_owned',
  version: 2,
  config_sha256: 'b'.repeat(64),
  generation: 2,
  max_ttl_seconds: 120,
};
const definition: GatewayDefinition = {
  name: '验收网关策略',
  sensor_id: 'sensor_owned',
  registration_id: 'registration_owned',
  enabled: true,
  trigger: 'rule',
  rule_id: '1003340',
  rule_revision: '1',
  scope: {
    sources: ['10.203.35.0/24'],
    destinations: ['10.203.36.0/24'],
  },
  lease_seconds: 15,
  valid_until: '2026-11-26T07:00:00Z',
  follow_up: {
    plugin_id: device.plugin_id,
    generation: 1,
    connector_id: device.connector_id,
    config_sha256: 'a'.repeat(64),
    target_side: 'destination',
    ttl_seconds: 60,
  },
};
const policy: GatewayPolicy = { id: 'policy_gateway', revision: 3, definition };
const archived: GatewayPolicy = {
  id: 'policy_old',
  revision: 6,
  definition: { ...definition, enabled: false, trigger: 'review', follow_up: undefined },
};
const sensor = {
  id: 'sensor_owned',
  registration_id: 'registration_owned',
  name: '实验采集器',
  active: true,
  status: 'online',
  health: {},
};
const wrappers: VueWrapper[] = [];
const body = () => new DOMWrapper(document.body);
function action(w: { findAll(selector: 'button'): DOMWrapper<HTMLButtonElement>[] }, title: string) {
  return w.findAll('button').find(node => node.text().replaceAll(' ', '') === title)!;
}
function field(text: string) {
  return body()
    .findAll('.ant-modal label')
    .find(label => label.text().startsWith(text))!;
}
async function screen(
  component: typeof GatewayBlocksView | typeof GatewayBlockSettings | typeof GatewayPolicyEditor,
  props = {},
) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/response/gateway-blocks', component: GatewayBlocksView },
      { path: '/response/actions', component: GatewayBlocksView },
      { path: '/sensors/tasks', component: GatewayBlocksView },
      { path: '/system/settings', component: GatewayBlockSettings },
    ],
  });
  await router.push('/response/gateway-blocks');
  await router.isReady();
  const w = mount(component, { attachTo: document.body, props, global: { plugins: [registerAnt, router] } });
  wrappers.push(w);
  await flushPromises();
  return w;
}
function mockSuccess() {
  request.mockImplementation(async (path: string, options?: { method?: string; body: Record<string, unknown> }) => {
    if (path === '/gateway-block/settings' && options?.method === 'PUT')
      return {
        revision: Number(options.body.expected_revision) + 1,
        enabled: options.body.enabled,
        per_minute: options.body.per_minute,
      };
    if (path.startsWith('/gateway-block/policies/') && options?.method === 'PUT')
      return {
        id: path.split('/').at(-1),
        revision: Number(options.body.expected_revision) + 1,
        definition: options.body.definition,
      };
    if (path.startsWith('/gateway-block/requests/')) return all.find(row => path.endsWith('/' + row.id));
    if (path.split('?')[0] === '/gateway-block/requests') {
      return path.includes('cursor=') ? { ...records, items: [], next_cursor: '', enabled: false } : records;
    }
    if (path === '/gateway-block/settings') return settings;
    if (path.split('?')[0] === '/gateway-block/policies') return { items: [policy, archived], next_cursor: '' };
    if (path.startsWith('/gateway-block/plugins?')) return { items: [device] };
    if (path === '/sensors') return { items: [sensor] };
    throw new Error('未登记的测试请求 ' + path);
  });
}

beforeEach(() => {
  vi.spyOn(Date, 'now').mockReturnValue(Date.parse(stamp));
  mockSuccess();
});
afterEach(() => wrappers.splice(0).forEach(w => w.unmount()));

describe('网关阻断记录', () => {
  it('分开展示原防火墙回读、三种出侧观察、研判修订和已执行的设备任务', async () => {
    const w = await screen(GatewayBlocksView);
    expect(w.get('h1').text()).toBe('网关阻断');
    expect(w.text()).toContain('可用网关 1 台');
    expect(w.get('a[href="/system/settings?section=gateway-block"]').text()).toBe('网关阻断设置');
    expect(w.get('[data-row-key="gateway_denied"]').text()).toContain('已拒绝');
    expect(w.get('[data-row-key="gateway_pending"]').text()).toContain('待授权');
    expect(w.get('[data-row-key="gateway_wait"]').text()).toContain('运行中');
    expect(w.get('[data-row-key="gateway_old"]').text()).toContain('暂无回读');
    for (const [id, symbols] of [
      [first.id, ['已回读', '流量暂停', '研判 v3', '核对设备任务', '已完成']],
      [continued.id, ['已回读', '仍有流量', '重连 10.203.35.3:42400', '未签发']],
      [unknown.id, ['结果未知', '租约不足以覆盖观察窗口', '观察口不可用']],
      [denied.id, ['暂无观察', '保护名单拦截']],
    ] as const) {
      await w.get(`[data-row-key="${id}"] button`).trigger('click');
      await flushPromises();
      const visible = body().get('.ant-modal');
      for (const label of symbols) expect(visible.text()).toContain(label);
      if (id === first.id) {
        expect(visible.get('a[href="/sensors/tasks?task=task_gateway"]').text()).toBe('核对网关任务');
        expect(visible.get('a[href="/response/actions?task=task_fixture"]').text()).toBe('核对设备任务');
      }
      await visible.get('.ant-modal-close').trigger('click');
    }
    await action(w, '下一页').trigger('click');
    await flushPromises();
    expect(w.text()).toContain('当前没有网关阻断请求');
    expect(w.text()).toContain('已停用');
    await action(w, '上一页').trigger('click');
    await flushPromises();
    expect(w.findAll('tr[data-row-key]')).toHaveLength(all.length);
    const pager = w.getComponent(ListPager);
    pager.vm.$emit('update:pageSize', 50);
    await flushPromises();
    expect(request.mock.calls.at(-1)?.[0]).toContain('limit=50');
  });

  it('处理目录和详情异常并可重试，保留接口返回的权限错误', async () => {
    request.mockRejectedValueOnce(new Error('目录不可用'));
    const w = await screen(GatewayBlocksView);
    expect(w.get('[role="alert"]').text()).toContain('目录不可用');
    await action(w, '重试').trigger('click');
    await flushPromises();
    request.mockRejectedValueOnce(new Error('详情不可用'));
    await w.get('[data-row-key="gateway_paused"] button').trigger('click');
    await flushPromises();
    expect(body().get('.ant-modal').text()).toContain('详情不可用');
    await action(body().get('.ant-modal'), '重试').trigger('click');
    await flushPromises();
    expect(body().get('.ant-modal').text()).toContain('网关阻断详情');
    expect(body().get('.ant-modal').text()).toContain('设备任务');
  });
});

describe('网关阻断设置', () => {
  it('可重试读取设置和策略，拒绝超限并刷新并发更新后的修订', async () => {
    request.mockRejectedValueOnce(new Error('设置读取失败')).mockRejectedValueOnce(new Error('策略读取失败'));
    const w = await screen(GatewayBlockSettings);
    expect(w.text()).toContain('设置读取失败');
    expect(w.text()).toContain('策略读取失败');
    for (const panel of w.findAll('.table-panel')) {
      await action(panel, '重试').trigger('click');
      await flushPromises();
    }
    const form = w.get('form');
    const limit = form.get('input[type=number]');
    await limit.setValue(61);
    await form.trigger('submit');
    expect(w.text()).toContain('每分钟限额须为 1 至 60');

    await limit.setValue(20);
    request.mockRejectedValueOnce(new Error('设置修订已变化'));
    await form.trigger('submit');
    await flushPromises();
    expect(w.text()).toContain('设置修订已变化');
    expect((limit.element as HTMLInputElement).value).toBe('20');
    request.mockResolvedValueOnce({ revision: 2, enabled: true, per_minute: 16 });
    await action(w, '刷新设置').trigger('click');
    await flushPromises();
    expect((w.get('form input[type=number]').element as HTMLInputElement).value).toBe('16');
    await action(w, '新建策略').trigger('click');
    await flushPromises();
    await action(body().get('.ant-modal'), '取消').trigger('click');
    expect(w.findComponent(GatewayPolicyEditor).exists()).toBe(false);
  });

  it('更新租户限额，编辑策略时要求明确选择新部署的插件代次', async () => {
    const w = await screen(GatewayBlockSettings);
    expect(w.text()).toContain('验收网关策略');
    expect(w.text()).toContain('未预授权');
    await w.get('form input[type=checkbox]').setValue(true);
    await w.get('form input[type=number]').setValue(17);
    await action(w, '保存设置').trigger('click');
    await flushPromises();
    expect(request).toHaveBeenCalledWith(
      '/gateway-block/settings',
      expect.objectContaining({
        method: 'PUT',
        body: { expected_revision: 0, enabled: true, per_minute: 17 },
      }),
    );
    expect(w.text()).toContain('网关设置已保存');
    await w.get('[data-row-key="policy_gateway"] button').trigger('click');
    await flushPromises();
    await body().get('.ant-modal form').trigger('submit');
    expect(body().get('.ant-modal').text()).toContain('选择当前部署的联动插件');
    const plugin = field('联动插件及设备').get('select');
    expect(plugin.findAll('option').map(x => x.text())).toContain('plugin_owned（原绑定）');
    await plugin.setValue(`plugin_owned/2/connector_owned/${device.config_sha256}`);
    await field('联动封禁时长').get('input').setValue(121);
    await body().get('.ant-modal form').trigger('submit');
    expect(body().get('.ant-modal').text()).toContain('封禁时长须为');
    await field('联动封禁时长').get('input').setValue(90);
    await body().get('.ant-modal form').trigger('submit');
    await flushPromises();
    expect(request).toHaveBeenCalledWith(
      '/gateway-block/policies/policy_gateway',
      expect.objectContaining({
        method: 'PUT',
        body: {
          expected_revision: 3,
          definition: {
            ...definition,
            follow_up: { ...definition.follow_up, generation: 2, config_sha256: device.config_sha256, ttl_seconds: 90 },
          },
        },
      }),
    );
    expect(w.findComponent(GatewayPolicyEditor).exists()).toBe(false);
  });

  it('默认停用新策略，验证规则、CIDR 和租约，并提供完整保存字段', async () => {
    const w = await screen(GatewayBlockSettings);
    await action(w, '新建策略').trigger('click');
    await flushPromises();
    const form = body().get('.ant-modal form');
    await form.trigger('submit');
    expect(form.text()).toContain('选择已注册的采集器');
    await field('策略标识').get('input').setValue('owned');
    await field('名称').get('input').setValue('实验新建');
    await field('采集器注册').get('select').setValue('sensor_owned/registration_owned');
    await form.trigger('submit');
    expect(form.text()).toContain('规则编号和修订');
    await field('规则编号').get('input').setValue('1003340');
    await field('规则修订').get('input').setValue('1');
    await form.trigger('submit');
    expect(form.text()).toContain('各填写 1 至 16 个 CIDR');
    await field('源侧 CIDR').get('textarea').setValue('10.203.35.0/24，10.203.37.0/24');
    await field('目的侧 CIDR').get('textarea').setValue('10.203.36.0/24');
    await field('网关租约').get('input').setValue(4);
    await form.trigger('submit');
    expect(form.text()).toContain('5 至 60 秒');
    await field('网关租约').get('input').setValue(10);
    await field('授权截止时间').get('input').setValue('');
    await form.trigger('submit');
    expect(form.text()).toContain('未来 24 小时');
    await field('授权截止时间').get('input').setValue('2026-11-26T07:00');
    request.mockRejectedValueOnce(new Error('策略修订已变化'));
    await form.trigger('submit');
    await flushPromises();
    expect(form.text()).toContain('策略修订已变化');
    await form.trigger('submit');
    await flushPromises();
    expect(request).toHaveBeenCalledWith(
      '/gateway-block/policies/owned',
      expect.objectContaining({
        body: {
          expected_revision: 0,
          definition: expect.objectContaining({
            enabled: false,
            rule_id: '1003340',
            lease_seconds: 10,
            scope: { sources: ['10.203.35.0/24', '10.203.37.0/24'], destinations: ['10.203.36.0/24'] },
          }),
        },
      }),
    );
  });

  it('设备和采集器目录不可用时仍能停用原策略', async () => {
    request.mockRejectedValueOnce(new Error('插件目录不可用')).mockRejectedValueOnce(new Error('采集器目录不可用'));
    const w = await screen(GatewayPolicyEditor, { policy });
    const form = body().get('.ant-modal form');
    expect(form.text()).toContain('原绑定');
    expect(form.text()).toContain('目录不可用');
    await action(form, '重读目录').trigger('click');
    await flushPromises();
    await action(form, '重读插件').trigger('click');
    await flushPromises();
    await field('启用策略').get('input').setValue(false);
    await form.trigger('submit');
    await flushPromises();
    expect(w.emitted('saved')).toHaveLength(1);
    expect(request).toHaveBeenCalledWith(
      '/gateway-block/policies/policy_gateway',
      expect.objectContaining({
        body: { expected_revision: 3, definition: { ...definition, enabled: false } },
      }),
    );
  });
});

describe('网关契约响应核对', () => {
  it('拒绝目录、身份和修订不完整的回执', async () => {
    const signal = new AbortController().signal;
    expect(formatGatewayFlow({ ...flow, source_ip: 'fd12:35::3', destination_ip: 'fd12:36::3' })).toBe(
      '[fd12:35::3]:42313 → [fd12:36::3]:8080',
    );
    for (const record of [
      { ...first, registration_id: 'invalid/' },
      { ...first, created_at: '' },
      { ...first, event_id: 'raw' },
      { ...first, flow: { ...first.flow, source_port: 0 } },
      { ...unknown, follow_up_state: 'unobserved' },
      { ...first, gateway_result: { ...first.gateway_result, request_id: 'other' } },
    ]) {
      request.mockResolvedValueOnce(record);
      await expect(readGatewayRecord(first.id, signal)).rejects.toThrow('身份不一致');
    }
    request.mockResolvedValueOnce(continued);
    await expect(readGatewayRecord(first.id, signal)).rejects.toThrow('身份不一致');
    for (const page of [
      { ...records, items: [first, first] },
      { ...records, next_cursor: 'unexpected' },
      { ...records, online_gateways: -1 },
      { ...records, last_day: { total: -1 } },
      { ...records, enabled: 'true' },
      null,
    ]) {
      request.mockResolvedValueOnce(page);
      await expect(readGatewayRecords('', 10, signal)).rejects.toThrow('响应不完整');
    }
    request
      .mockResolvedValueOnce({ items: [device, device] })
      .mockResolvedValueOnce({ items: [{ ...device, generation: 0 }] });
    for (let i = 0; i < 2; i++)
      await expect(readGatewayDevices(sensor.id, sensor.registration_id, signal)).rejects.toThrow('不可核对');
    request.mockResolvedValueOnce({
      items: [{ ...policy, definition: { ...definition, scope: null } }],
      next_cursor: '',
    });
    await expect(readGatewayPolicies('', 10, signal)).rejects.toThrow('响应不完整');
    request.mockResolvedValueOnce({ ...settings, per_minute: 0 });
    await expect(readGatewaySettings(signal)).rejects.toThrow('响应不完整');
    request.mockResolvedValueOnce({ ...settings, revision: 6 });
    await expect(saveGatewaySettings(0, true, 10, signal)).rejects.toThrow('回执不一致');
    request.mockResolvedValueOnce({ ...policy, id: 'different' });
    await expect(saveGatewayPolicy(policy.id, 3, definition, signal)).rejects.toThrow('回执不一致');
  });
});
