<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import type { MetricSpec, PageSpec, PreviewState } from '../models';
import PageHeader from '../components/PageHeader.vue';
import MetricBar from '../../../web/packages/shared/src/components/MetricBar.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import StatePanel from '../components/StatePanel.vue';
import HelpNote from '../components/HelpNote.vue';
import { bypassEnabled, bypassInterface } from '../composables/systemSettings';

// 旁路阻断：采集器通过独立的注入网口向命中的连接双向发送 TCP RST（UDP 发 ICMP 不可达）。
// 开关、注入上限和阻断策略属于系统设置，本页只看阻断记录。
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
    injected: 'RST ×2',
    effect: '已终止',
    follow: '防火墙封禁 24 小时',
  },
  {
    id: 'BYPASS-0002',
    time: '2026-09-30 09:21:07',
    session: '198.51.100.29:40112 → 10.20.1.20:8080',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0006',
    injected: 'RST ×2',
    effect: '已终止',
    follow: '防火墙封禁 2 小时',
  },
  {
    id: 'BYPASS-0003',
    time: '2026-09-30 08:58:30',
    session: '198.51.100.24:38820 → 10.20.1.15:443',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0001',
    injected: 'RST ×2',
    effect: '仍有流量',
    follow: '4 秒后重连，已封禁',
  },
  {
    id: 'BYPASS-0004',
    time: '2026-09-30 08:40:12',
    session: '10.20.1.61:53011 → 203.0.113.9:443',
    protocol: 'QUIC',
    policy: 'C2 外联即时断开',
    alert: 'ALERTS-0012',
    injected: 'ICMP 不可达 ×1',
    effect: '结果未知',
    follow: '等待插件确认',
  },
  {
    id: 'BYPASS-0005',
    time: '2026-09-30 08:12:55',
    session: '198.51.100.31:44001 → 10.20.0.1:22',
    protocol: 'TCP',
    policy: '高危漏洞利用断开',
    alert: 'ALERTS-0015',
    injected: '未注入',
    effect: '保护名单拦截',
    follow: '目标属于管理地址',
  },
]);
const recordColumns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 108 },
  { title: '时间', dataIndex: 'time', key: 'time', width: 158 },
  { title: '连接', dataIndex: 'session', key: 'session', width: 306, ellipsis: true },
  { title: '命中策略', dataIndex: 'policy', key: 'policy', width: 150, ellipsis: true },
  { title: '触发告警', dataIndex: 'alert', key: 'alert', width: 104 },
  { title: '注入', dataIndex: 'injected', key: 'injected', width: 112 },
  { title: '效果观察', dataIndex: 'effect', key: 'effect', width: 116 },
  { title: '后续', dataIndex: 'follow', key: 'follow', ellipsis: true },
];
const empty = computed(() => props.state === 'empty');
const metrics = computed<MetricSpec[]>(() => [
  { label: '今日阻断连接', value: empty.value ? '0' : '37' },
  { label: '确认终止', value: empty.value ? '0' : '31' },
  { label: '仍有流量', value: empty.value ? '0' : '4', tone: 'warning' },
  { label: '结果未知', value: empty.value ? '0' : '2', tone: 'warning' },
  { label: '保护名单拦截', value: empty.value ? '0' : '5' },
]);
const effectTones = { 已终止: 'success', 仍有流量: 'warning', 结果未知: 'warning', 保护名单拦截: 'neutral' } as const;

const settingsLink = { path: '/page/system-settings', query: { section: 'bypass' } };
function openSettings() {
  void router.push(settingsLink);
}
</script>

<template>
  <PageHeader :title="page.title" :description="page.description">
    <a-space wrap :size="16">
      <span class="bypass-now">旁路阻断：{{ bypassEnabled ? '启用' : '未启用' }}</span>
      <span class="bypass-now"><span class="status-dot success"></span>注入网口 {{ bypassInterface }} · 链路正常</span>
      <router-link class="bypass-edit" :to="settingsLink">修改</router-link>
    </a-space>
  </PageHeader>
  <HelpNote
    message="旁路阻断是尽力而为：注入的 RST 可能晚于对端数据到达，对 QUIC 等 UDP 协议效果有限，对方也可以重连。它用来先断开连接争取时间，持久封禁由联动插件在防火墙上完成。"
  />
  <HelpNote message="本页为合成示例，不向任何网络发包。" />

  <StatePanel v-if="state === 'loading' || state === 'error'" :state="state" @action="emit('state', 'data')" />
  <template v-else>
    <MetricBar :items="metrics" />
    <a-alert
      v-if="!bypassEnabled"
      class="page-notice"
      type="warning"
      show-icon
      message="旁路阻断未启用，不会产生新的阻断记录。"
    >
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
        state="empty"
        title="还没有阻断记录"
        description="启用阻断策略并命中后，每次注入和效果观察会出现在这里。"
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
