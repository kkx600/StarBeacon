<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import type { MetricSpec, PageSpec, PreviewState } from '../models';
import PageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';
import MetricBar from '../../../web/packages/shared/src/components/MetricBar.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue';
import HelpNote from '../components/HelpNote.vue';
import { bypassEnabled, bypassInterface } from '../composables/systemSettings';

// 网关阻断记录分别展示防火墙回读、出侧观察与联动结果。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const router = useRouter();

const records = ref([
  {
    id: 'BYPASS-0001',
    time: '2026-09-30 09:36:48',
    session: '10.20.1.44:51822 → 203.0.113.80:443',
    protocol: 'TCP',
    policy: 'C2 外联即时断开',
    alert: 'ALERTS-0002',
    readback: '已回读',
    effect: '流量暂停',
    follow: '设备租约已回读 · 60 秒',
  },
  {
    id: 'BYPASS-0002',
    time: '2026-09-30 09:21:07',
    session: '198.51.100.29:40112 → 10.20.1.20:8080',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0006',
    readback: '已回读',
    effect: '流量暂停',
    follow: '未预授权',
  },
  {
    id: 'BYPASS-0003',
    time: '2026-09-30 08:58:30',
    session: '198.51.100.24:38820 → 10.20.1.15:443',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0001',
    readback: '已回读',
    effect: '仍有流量',
    follow: '观察到重连 · 已通知值班',
  },
  {
    id: 'BYPASS-0004',
    time: '2026-09-30 08:40:12',
    session: '10.20.1.61:53011 → 203.0.113.9:443',
    protocol: 'QUIC',
    policy: 'C2 外联即时断开',
    alert: 'ALERTS-0012',
    readback: '已回读',
    effect: '结果未知',
    follow: '未签发 · 观察口不可用',
  },
  {
    id: 'BYPASS-0005',
    time: '2026-09-30 08:12:55',
    session: '198.51.100.31:44001 → 10.20.0.1:22',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0015',
    readback: '已拒绝',
    effect: '暂无观察',
    follow: '目标属于管理地址',
  },
]);
const recordColumns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 108 },
  { title: '时间', dataIndex: 'time', key: 'time', width: 158 },
  { title: '连接', dataIndex: 'session', key: 'session', width: 306, ellipsis: true },
  { title: '命中策略', dataIndex: 'policy', key: 'policy', width: 150, ellipsis: true },
  { title: '触发告警', dataIndex: 'alert', key: 'alert', width: 104 },
  { title: '防火墙回读', dataIndex: 'readback', key: 'readback', width: 112 },
  { title: '流量观察', dataIndex: 'effect', key: 'effect', width: 116 },
  { title: '联动封禁', dataIndex: 'follow', key: 'follow', ellipsis: true },
];
const empty = computed(() => props.state === 'empty');
const metrics = computed<MetricSpec[]>(() => [
  { label: '近 24 小时请求', value: empty.value ? '0' : '42' },
  { label: '流量暂停', value: empty.value ? '0' : '31' },
  { label: '仍有流量', value: empty.value ? '0' : '4', tone: 'warning' },
  { label: '结果未知', value: empty.value ? '0' : '2', tone: 'warning' },
  { label: '保护名单拦截', value: empty.value ? '0' : '5' },
]);
const effectTones = { 流量暂停: 'success', 仍有流量: 'warning', 结果未知: 'warning', 暂无观察: 'neutral' } as const;

const settingsLink = { path: '/page/system-settings', query: { section: 'bypass' } };
function openSettings() {
  void router.push(settingsLink);
}
</script>

<template>
  <PageHeader :help-entries="helpEntries" :title="page.title" :description="page.description">
    <a-space wrap :size="16">
      <span class="bypass-now">网关阻断 {{ bypassEnabled ? '已启用' : '已停用' }}</span>
      <span class="bypass-now"><span class="status-dot success"></span>观察口 {{ bypassInterface }} · 链路正常</span>
      <router-link class="bypass-edit" :to="settingsLink">网关阻断设置</router-link>
    </a-space>
  </PageHeader>
  <HelpNote message="受控网关对单条连接应用限时防火墙条目。出侧观察和联动设备回读分别记入记录。" />

  <StatePanel
    v-if="state === 'loading' || state === 'error'"
    :loading="state === 'loading'"
    :error="state === 'error'"
    @retry="emit('state', 'data')"
  />
  <template v-else>
    <MetricBar :items="metrics" />
    <a-alert v-if="!bypassEnabled" class="page-notice" type="warning" show-icon message="网关阻断已停用。">
      <template #action>
        <a-button type="link" size="small" @click="openSettings">去启用</a-button>
      </template>
    </a-alert>
    <section class="panel table-panel">
      <div class="table-toolbar">
        <div><h2>阻断记录</h2></div>
      </div>
      <StatePanel
        v-if="empty"
        empty
        title="还没有阻断记录"
        description="这里显示网关阻断请求、条目回读和流量观察。"
        action="管理阻断策略"
        @action="openSettings"
      />
      <a-table
        v-else
        :columns="recordColumns"
        :data-source="records"
        row-key="id"
        size="small"
        :scroll="{ x: 1170 }"
        :pagination="tablePagination()"
      >
        <template #bodyCell="{ column, record, text }">
          <span v-if="['id', 'session', 'alert'].includes(String(column.key))" class="mono">{{ text }}</span>
          <span v-else-if="column.key === 'time'" class="tabular">{{ text }}</span>
          <StatusTag v-else-if="column.key === 'effect'" :value="text" :tone="statusTone(effectTones, record.effect)" />
        </template>
      </a-table>
    </section>
  </template>
</template>

<style scoped>
.bypass-now {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--muted);
  font-size: 12px;
}
.bypass-edit {
  font-size: 12px;
}
</style>
