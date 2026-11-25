import { webcrypto } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import { Select } from 'ant-design-vue';
import { createMemoryHistory, createRouter } from 'vue-router';
import { registerAnt } from '../packages/shared/src/ant';
import { ApiClient } from '../packages/shared/src/api';
import ListPager from '../packages/shared/src/components/ListPager.vue';
import PacketRetentionEditor from '../packages/shared/src/components/PacketRetentionEditor.vue';
import TimeRangeField from '../packages/shared/src/components/TimeRangeField.vue';
import type {
  PacketRetentionObservation,
  PacketRetentionStatus,
  PacketStorageSettings,
} from '../packages/shared/src/packetRetention';
import FullTrafficWorkspace from '../platform/src/features/traffic/FullTrafficWorkspace.vue';
import PacketStorageSettingsWorkspace from '../platform/src/features/settings/PacketStorageSettings.vue';
import LocalPacketRetention from '../collector/src/features/network/LocalPacketRetention.vue';
import {
  flowQuery,
  flowSource,
  validPacketFlowPage,
  defaultFlowFilters,
  type PacketFlowQuery,
} from '../platform/src/features/traffic/packetFlows';

const { request, download, local } = vi.hoisted(() => ({ request: vi.fn(), download: vi.fn(), local: vi.fn() }));
vi.mock('../platform/src/session', async () => {
  const { shallowRef } = await import('vue');
  return {
    session: {
      api: { request, downloadPacket: download },
      current: shallowRef({ id: 'operator', tenant_id: 'tenant_f', role: 'admin' }),
    },
  };
});
vi.mock('../collector/src/session', () => ({ session: { api: { request: local } } }));

let stamp: string;
const digest = 'a'.repeat(64);
const observation: PacketRetentionObservation = {
  policy: {
    network_domain: 'test_domain',
    revision: 2,
    mode: 'smart',
    encrypted_bytes: 16384,
    plain_bytes: 65536,
    dedup_millis: 50,
  },
  sha256: digest,
  origin: 'file',
};
function status(configuration = observation): PacketRetentionStatus {
  return {
    state: 'ready',
    observed_at: stamp,
    configuration,
    reserved_bytes: '1048576',
    quota_bytes: '1073741824',
    segment_bytes: '16777216',
    rotate_seconds: 300,
  };
}
function storage(configuration = observation): PacketStorageSettings {
  return {
    sensors: [{ id: 'sensor_a', name: '验收采集器', fresh: true, can_apply: true, status: status(configuration) }],
    sensors_limited: false,
    warm_state: 'ready',
    cold_state: 'unmanaged',
    warm: {
      backend: 'filesystem',
      measured: true,
      free_bytes: '50000',
      total_bytes: '100000',
      floor_bytes: '1000',
      limit_bytes: '0',
      archives: '2',
      stored_bytes: '500',
      retention_days: 180,
      oldest_created_at: stamp,
    },
  };
}
function page(query: PacketFlowQuery) {
  const items = ['retained', 'policy_truncated', 'metadata_only']
    .map((retention, index) => ({
      event_id: `flow_${index}`,
      tenant_id: 'tenant_f',
      sensor_id: 'sensor_a',
      source_generation_id: `packet_${index}`,
      '@timestamp': stamp,
      observed_at: stamp,
      source: { ip: '192.0.2.3', port: 42000 },
      destination: { ip: '2001:db8::13', port: 8080 },
      network: { transport: 'tcp' },
      event: { kind: 'flow_segment', original: '' },
      http: {},
      suricata: {},
      rule: {},
      details: {
        state: 'available',
        truncated: false,
        flow: null,
        tls: null,
        dns: null,
        source_macs: [],
        destination_macs: [],
        community_id: '',
        direction: '',
        packet_source: '',
        segment: {
          schema: 'starbeacon.packet-flow.v1',
          archive_id: `packet_${index}`,
          manifest_sha256: digest,
          archive_raw_sha256: 'b'.repeat(64),
          run_id: 'capture_f',
          interface: 'eth0',
          window_start: stamp,
          window_end: stamp,
          first_observed: stamp,
          last_observed: stamp,
          vlan: '',
          retention,
          original_bytes: '1000',
          retained_bytes: ['1000', '50', '0'][index],
          retained_packets: ['10', '1', '0'][index],
          kernel_drops: '0',
          limited: false,
        },
      },
    }))
    .filter(item => !query.session_retention || item.details.segment.retention === query.session_retention);
  return { items, total: items.length, page: query.page, page_size: query.page_size };
}

beforeEach(() => {
  stamp = new Date(Date.now() - 60000).toISOString();
  vi.stubGlobal('crypto', webcrypto);
  request.mockReset();
  local.mockReset();
  download.mockReset();
});

async function router() {
  const active = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: FullTrafficWorkspace },
      { path: '/system/settings', component: PacketStorageSettingsWorkspace },
      { path: '/sensors/tasks', component: { template: '<div />' } },
    ],
  });
  await active.push('/');
  return active;
}

describe('全流量工程页面', () => {
  it('检索真实分段字段并按留存状态限制查看和下载', async () => {
    request.mockImplementation((path, input) =>
      Promise.resolve(path === '/packet-storage' ? storage() : page(input.body)),
    );
    download.mockRejectedValue(new Error('归档对象无法读取'));
    const wrapper = mount(FullTrafficWorkspace, { global: { plugins: [registerAnt, await router()] } });
    try {
      await flushPromises();
      expect(wrapper.text()).toContain('智能留存');
      expect(wrapper.get('[data-row-key="flow_0"]').text()).toContain('窗口内全量留存');
      const partial = wrapper.get('[data-row-key="flow_1"]');
      expect(partial.text()).toContain('按策略截断');
      expect(wrapper.get('[data-row-key="flow_2"]').findAll('button')).toHaveLength(0);
      expect(wrapper.get('[data-row-key="flow_2"]').text()).toContain('仅元数据');
      await partial
        .findAll('button')
        .find(item => item.text() === '下载留存报文')!
        .trigger('click');
      await flushPromises();
      expect(download).toHaveBeenCalledWith(
        '/packet-archives/packet_1/flow-snapshot',
        expect.any(AbortSignal),
        expect.objectContaining({
          retention: 'policy_truncated',
          flow: expect.objectContaining({ endpoint_a: '192.0.2.3:42000', endpoint_b: '[2001:db8::13]:8080' }),
        }),
      );
      expect(wrapper.text()).toContain('归档对象无法读取');
      await wrapper.get('input[aria-label="端点 A"]').setValue('192.0.2.0/24');
      await wrapper
        .findAll('button')
        .find(item => item.text() === '查询')!
        .trigger('click');
      await flushPromises();
      expect(request).toHaveBeenLastCalledWith(
        '/traffic/search',
        expect.objectContaining({
          body: expect.objectContaining({ event_kind: 'flow_segment', endpoint_a: '192.0.2.0/24' }),
        }),
      );
      expect(wrapper.get('a[href="/system/settings?section=traffic"]').text()).toBe('全流量存储');
    } finally {
      wrapper.unmount();
    }
  });

  it('拒绝伪造留存计数和目标条件，看不到原包的分段没有读取请求', () => {
    const query = flowQuery(defaultFlowFilters(), Date.now(), 20);
    const data: unknown = page(query);
    expect(validPacketFlowPage(data, query, 'tenant_f')).toBe(true);
    if (!validPacketFlowPage(data, query, 'tenant_f')) throw new Error('测试数据无效');
    expect(flowSource(data.items[2]!)).toBeNull();
    expect(validPacketFlowPage(data, { ...query, session_retention: 'metadata_only' }, 'tenant_f')).toBe(false);
    data.items[2]!.details.segment.retained_packets = '1';
    expect(validPacketFlowPage(data, query, 'tenant_f')).toBe(false);
    expect(() => flowQuery({ ...defaultFlowFilters(), hours: 0 }, Date.now(), 20)).toThrow('起止时间');
  });

  it('快照保留截断标记，本页导出包含仅元数据记录', async () => {
    request.mockImplementation((path: string, input) =>
      Promise.resolve(path === '/packet-storage' ? storage() : page(input.body)),
    );
    const raw = new Blob(['pcapng'], { type: 'application/x-pcapng' });
    download.mockResolvedValue(raw);
    const created = vi.fn().mockReturnValueOnce('blob:pcap').mockReturnValueOnce('blob:csv');
    const revoked = vi.fn();
    vi.stubGlobal(
      'URL',
      class extends URL {
        static createObjectURL = created;
        static revokeObjectURL = revoked;
      },
    );
    const files: string[] = [];
    const anchor = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      files.push(this.download);
    });
    const wrapper = mount(FullTrafficWorkspace, { global: { plugins: [registerAnt, await router()] } });
    try {
      await flushPromises();
      const partial = wrapper.get('[data-row-key="flow_1"]');
      await partial
        .findAll('button')
        .find(item => item.text() === '下载留存报文')!
        .trigger('click');
      await flushPromises();
      expect(created).toHaveBeenNthCalledWith(1, raw);
      await wrapper
        .findAll('button')
        .find(item => item.text() === '导出本页')!
        .trigger('click');
      expect(files).toEqual(['snapshot-flow_1-partial.pcapng', 'starbeacon-session-segments.csv']);
      expect(revoked).toHaveBeenCalledWith('blob:pcap');
      const csv = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsText(created.mock.calls[1]![0] as Blob);
      });
      expect(csv.split('\r\n')).toHaveLength(4);
      expect(csv).toContain('"flow_2","sensor_a"');
      expect(csv).toContain('"1000","0","仅元数据"');
    } finally {
      wrapper.unmount();
      anchor.mockRestore();
    }
    expect(revoked).toHaveBeenCalledWith('blob:csv');
  });

  it('检索拒绝错页回执，重试保留页码，重置恢复默认条件', async () => {
    let invalid = true;
    request.mockImplementation((path: string, { body }) => {
      if (path === '/packet-storage') return Promise.resolve(storage());
      const data = page(body);
      if (invalid) return Promise.resolve({ ...data, page: 9 });
      return Promise.resolve(body.page === 1 ? data : { ...data, items: [] });
    });
    const wrapper = mount(FullTrafficWorkspace, { global: { plugins: [registerAnt, await router()] } });
    const button = (label: string) =>
      wrapper.findAll('button').find(item => item.text().replace(/\s+/g, '') === label)!;
    try {
      await flushPromises();
      expect(wrapper.text()).toContain('会话分段与检索条件或归档来源不一致');
      expect(button('导出本页').attributes('disabled')).toBeDefined();
      invalid = false;
      await button('重试').trigger('click');
      await flushPromises();
      expect(wrapper.find('[data-row-key="flow_1"]').exists()).toBe(true);
      const pager = wrapper.getComponent(ListPager);
      pager.vm.$emit('change', 1001, 20);
      await flushPromises();
      expect(request).toHaveBeenLastCalledWith(
        '/traffic/search',
        expect.objectContaining({ body: expect.objectContaining({ page: 1 }) }),
      );
      invalid = true;
      pager.vm.$emit('change', 2, 20);
      await flushPromises();
      invalid = false;
      await button('重试').trigger('click');
      await flushPromises();
      expect(pager.props('page')).toBe(2);
      expect(wrapper.text()).toContain('没有找到会话分段');
      wrapper.getComponent(TimeRangeField).vm.$emit('update:preset', 0);
      await button('查询').trigger('click');
      expect(wrapper.text()).toContain('请选择有效的起止时间');
      await button('重置').trigger('click');
      await flushPromises();
      expect(pager.props('page')).toBe(1);
      expect(wrapper.text()).not.toContain('请选择有效的起止时间');
    } finally {
      wrapper.unmount();
    }
  });

  it('签名任务提交后等待采集器回读才显示新修订', async () => {
    const next: PacketRetentionObservation = {
      policy: { ...observation.policy, revision: 3, mode: 'full' },
      sha256: 'b'.repeat(64),
      origin: 'platform',
      task_id: 'task_f',
      applied_at: stamp,
    };
    let current = observation;
    request.mockImplementation((path: string) => {
      if (path === '/packet-storage') return Promise.resolve(storage(current));
      if (path === '/tasks/task_f')
        return Promise.resolve({
          id: 'task_f',
          sensor_id: 'sensor_a',
          kind: 'packet.retention.configure',
          state: 'succeeded',
          receipt: { result: next },
        });
      if (path === '/sensors/sensor_a/packet-retention') return Promise.resolve({ task_id: 'task_f' });
      throw new Error('意外请求');
    });
    const wrapper = mount(PacketStorageSettingsWorkspace, { global: { plugins: [registerAnt, await router()] } });
    try {
      await flushPromises();
      expect(wrapper.text()).toContain('热层 · 所选采集器已预留');
      expect(wrapper.text()).toContain('平台未纳管冷层用量');
      wrapper
        .getComponent(PacketRetentionEditor)
        .vm.$emit('save', { expected_revision: 2, expected_sha256: digest, policy: next.policy });
      await flushPromises();
      expect(request).toHaveBeenCalledWith(
        '/sensors/sensor_a/packet-retention',
        expect.objectContaining({
          body: expect.objectContaining({ expected_revision: 2 }),
          headers: { 'Idempotency-Key': expect.any(String) },
        }),
      );
      expect(wrapper.text()).toContain('等待最新配置同步');
      expect(wrapper.text()).not.toContain('采集器已回读修订 3');
      current = next;
      await wrapper
        .findAll('button')
        .find(item => item.text().replace(/\s/g, '') === '刷新')!
        .trigger('click');
      await flushPromises();
      expect(wrapper.text()).toContain('采集器已回读修订 3');
    } finally {
      wrapper.unmount();
    }
  });

  it('采集器本地编辑提交同一修订和摘要契约', async () => {
    const next: PacketRetentionObservation = {
      policy: { ...observation.policy, revision: 3, mode: 'full' },
      sha256: 'c'.repeat(64),
      origin: 'local',
      applied_at: stamp,
    };
    local.mockResolvedValueOnce(status()).mockResolvedValueOnce(next);
    const wrapper = mount(LocalPacketRetention, { global: { plugins: [registerAnt] } });
    try {
      await flushPromises();
      const editor = wrapper.getComponent(PacketRetentionEditor);
      editor.getComponent(Select).vm.$emit('update:value', 'full');
      await flushPromises();
      await editor.get('form').trigger('submit');
      await flushPromises();
      expect(local).toHaveBeenLastCalledWith(
        '/packet-retention',
        expect.objectContaining({
          method: 'PUT',
          body: expect.objectContaining({
            expected_revision: 2,
            expected_sha256: digest,
            policy: expect.objectContaining({ revision: 3, mode: 'full' }),
          }),
        }),
      );
      expect(wrapper.text()).toContain('本机已保存修订 3');
    } finally {
      wrapper.unmount();
    }
  });

  it('活跃草稿遇到平台新修订必须重新载入，旧草稿不能覆盖', async () => {
    const next: PacketRetentionObservation = {
      policy: { ...observation.policy, revision: 3, mode: 'smart', dedup_millis: 80 },
      sha256: 'c'.repeat(64),
      origin: 'platform',
      task_id: 'task_f',
      applied_at: stamp,
    };
    const wrapper = mount(PacketRetentionEditor, { props: { observation }, global: { plugins: [registerAnt] } });
    try {
      await wrapper.get('#retention-observe').setValue('192.0.2.0/24 192.0.2.0/24');
      await wrapper.get('form').trigger('submit');
      await flushPromises();
      expect(wrapper.text()).toContain('不能重复');
      await wrapper.get('#retention-observe').setValue('192.0.2.0/24');
      await wrapper.setProps({ observation: next });
      expect(wrapper.text()).toContain('采集器已有新修订');
      await wrapper.get('form').trigger('submit');
      await flushPromises();
      expect(wrapper.emitted('save')).toBeUndefined();
      await wrapper
        .findAll('button')
        .find(item => item.text() === '载入当前配置')!
        .trigger('click');
      await wrapper.get('#retention-protect').setValue('203.0.113.0/24');
      await wrapper.get('form').trigger('submit');
      await flushPromises();
      expect(wrapper.emitted('save')).toEqual([
        [
          {
            expected_revision: 3,
            expected_sha256: next.sha256,
            policy: { ...next.policy, revision: 4, protect: ['203.0.113.0/24'], observe: [] },
          },
        ],
      ]);
    } finally {
      wrapper.unmount();
    }
  });

  it('导出拒绝用完整会话头替代被裁剪快照的保留标签', async () => {
    const query = flowQuery(defaultFlowFilters(), Date.now(), 20);
    const data: unknown = page(query);
    if (!validPacketFlowPage(data, query, 'tenant_f')) throw new Error('测试数据无效');
    const source = flowSource(data.items[1]!)!;
    const send = vi
      .fn()
      .mockResolvedValue(
        new Response('', { headers: { 'X-Session-Completeness': 'full_session', 'X-Packet-Retention': 'retained' } }),
      );
    vi.stubGlobal('fetch', send);
    const client = new ApiClient('/api/v1');
    await expect(client.downloadPacket('/packet-archives/packet_1/flow-snapshot', undefined, source)).rejects.toThrow(
      '导出范围',
    );
    expect(send.mock.calls[0]?.[1]?.body).toEqual(JSON.stringify(source.flow));
  });
});
