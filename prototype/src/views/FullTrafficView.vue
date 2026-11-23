<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { DownloadOutlined, SearchOutlined } from '@ant-design/icons-vue';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import type { MetricSpec, PageSpec, PreviewState } from '../models';
import PageHeader from '../components/PageHeader.vue';
import MetricBar from '../../../web/packages/shared/src/components/MetricBar.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import StatePanel from '../components/StatePanel.vue';
import HelpNote from '../components/HelpNote.vue';
import { retentionPolicy } from '../composables/systemSettings';

// 全流量回溯：按时间和五元组找到任意会话，查看它的原包留存情况并下载。
// 会话元数据全部保留；原包按留存策略保存，被截断的会话明确标记。留存策略属于系统设置，本页只读显示。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const message = useFeedback();
const router = useRouter();

const sessions = ref([
  {
    id: 'FLOW-0001',
    start: '2026-09-30 09:42:16',
    source: '198.51.100.24:38820',
    destination: '10.20.1.15:443',
    app: 'HTTPS',
    observed: '4.2 MB',
    stored: '4.2 MB',
    retention: '完整',
    alert: 'ALERTS-0001',
  },
  {
    id: 'FLOW-0002',
    start: '2026-09-30 09:41:50',
    source: '10.20.3.18:52210',
    destination: '203.0.113.44:443',
    app: 'TLS · 视频',
    observed: '1.8 GB',
    stored: '18 KB',
    retention: '按策略截断',
    alert: '—',
  },
  {
    id: 'FLOW-0003',
    start: '2026-09-30 09:41:12',
    source: '10.20.1.16:53412',
    destination: '203.0.113.9:53',
    app: 'DNS',
    observed: '2.1 KB',
    stored: '2.1 KB',
    retention: '完整',
    alert: 'ALERTS-0002',
  },
  {
    id: 'FLOW-0004',
    start: '2026-09-30 09:40:35',
    source: '10.20.2.7:49822',
    destination: '10.20.9.3:445',
    app: 'SMB · 文件传输',
    observed: '620 MB',
    stored: '2.0 MB',
    retention: '按策略截断',
    alert: '—',
  },
  {
    id: 'FLOW-0005',
    start: '2026-09-30 09:39:58',
    source: '10.20.1.61:53011',
    destination: '203.0.113.9:443',
    app: 'QUIC',
    observed: '96 MB',
    stored: '16 KB',
    retention: '按策略截断',
    alert: '—',
  },
  {
    id: 'FLOW-0006',
    start: '2026-09-30 09:39:20',
    source: '10.20.4.40:41200',
    destination: '10.20.1.20:8080',
    app: 'HTTP',
    observed: '38 KB',
    stored: '38 KB',
    retention: '完整',
    alert: '—',
  },
  {
    id: 'FLOW-0007',
    start: '2026-07-02 11:15:09',
    source: '10.20.5.5:50100',
    destination: '198.51.100.90:22',
    app: 'SSH',
    observed: '12 MB',
    stored: '—',
    retention: '仅元数据',
    alert: '—',
  },
]);
const columns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 96 },
  { title: '开始时间', dataIndex: 'start', key: 'start', width: 158 },
  { title: '源', dataIndex: 'source', key: 'source', width: 156 },
  { title: '目的', dataIndex: 'destination', key: 'destination', width: 156 },
  { title: '协议与应用', dataIndex: 'app', key: 'app', ellipsis: true },
  { title: '观测字节', dataIndex: 'observed', key: 'observed', width: 84 },
  { title: '落盘字节', dataIndex: 'stored', key: 'stored', width: 84 },
  { title: '原包留存', dataIndex: 'retention', key: 'retention', width: 116 },
  { title: '关联告警', dataIndex: 'alert', key: 'alert', width: 104 },
  { title: '操作', key: 'actions', width: 116, fixed: 'right' as const },
];
const empty = computed(() => props.state === 'empty');
const rows = computed(() => (empty.value ? [] : sessions.value));
const metrics = computed<MetricSpec[]>(() => [
  { label: '近 24 小时观测', value: empty.value ? null : '8.6', suffix: 'TB', missingReason: '未取得流量观测' },
  {
    label: '实际落盘',
    value: empty.value ? null : '0.61',
    suffix: 'TB',
    note: '节省 92.9%',
    missingReason: '暂无原包落盘统计',
  },
  { label: '会话记录', value: empty.value ? '0' : '1.2 亿' },
  { label: '预计可回溯', value: empty.value ? null : '180', suffix: '天', missingReason: '缺少用于估算的存储观测' },
  { label: '分段索引占原包', value: empty.value ? null : '0.3%', missingReason: '暂无分段索引统计' },
]);
const retentionTones = { 完整: 'success', 仅元数据: 'neutral', 按策略截断: 'warning' } as const;

const query = ref({ window: '最近 24 小时', source: '', destination: '', retention: undefined as string | undefined });
const settingsLink = { path: '/page/system-settings', query: { section: 'traffic' } };
</script>

<template>
  <PageHeader :title="page.title" :description="page.description">
    <a-space wrap :size="16">
      <span class="traffic-policy-now">
        留存策略：{{ retentionPolicy }}
        <router-link class="traffic-policy-edit" :to="settingsLink">修改</router-link>
      </span>
      <a-button @click="message.success('本地示例：已导出当前会话清单。')"><DownloadOutlined />导出</a-button>
    </a-space>
  </PageHeader>
  <HelpNote
    message="每条会话的元数据（谁连谁、协议、时间、字节数）全部保留。原包按留存策略保存：被截断的会话标记为“按策略截断”，下载时只包含实际保存的部分，不会当作完整会话。"
  />
  <HelpNote
    message="存储方式：原包按时间切成 1 GiB 分段，分段内每 1 MiB 独立压缩，读取会话时只解压涉及的部分；每个分段带一个本地索引（五元组到压缩块），逐包位置不写入检索集群。"
  />
  <HelpNote message="本页为合成示例，数字不代表实测结果。" />

  <StatePanel v-if="state === 'loading' || state === 'error'" :state="state" @action="emit('state', 'data')" />
  <template v-else>
    <MetricBar :items="metrics" />

    <section class="panel filter-panel" aria-label="会话检索">
      <div class="filter-grid traffic-filter">
        <label
          ><span>时间</span
          ><a-select
            v-model:value="query.window"
            :options="
              ['最近 1 小时', '最近 24 小时', '最近 7 天', '最近 30 天', '自定义'].map(value => ({
                value,
                label: value,
              }))
            "
        /></label>
        <label
          ><span>源</span><a-input v-model:value="query.source" placeholder="IP、网段或 IP:端口" allow-clear
        /></label>
        <label
          ><span>目的</span><a-input v-model:value="query.destination" placeholder="IP、网段或 IP:端口" allow-clear
        /></label>
        <label
          ><span>原包留存</span
          ><a-select
            v-model:value="query.retention"
            placeholder="全部"
            allow-clear
            :options="['完整', '按策略截断', '仅元数据'].map(value => ({ value, label: value }))"
        /></label>
        <div class="filter-buttons">
          <a-button type="primary"><SearchOutlined />查询</a-button>
          <a-button @click="query = { window: '最近 24 小时', source: '', destination: '', retention: undefined }"
            >重置</a-button
          >
        </div>
      </div>
    </section>

    <section class="panel table-panel">
      <div class="table-toolbar">
        <div><h2>会话</h2></div>
      </div>
      <StatePanel
        v-if="!rows.length"
        state="empty"
        title="没有找到会话"
        description="当前时间范围内没有会话记录。请确认探针在线，或放宽时间范围。"
        action="查看留存策略"
        @action="router.push(settingsLink)"
      />
      <a-table
        v-else
        :columns="columns"
        :data-source="rows.filter(row => !query.retention || row.retention === query.retention)"
        row-key="id"
        size="small"
        :scroll="{ x: 1170 }"
        :pagination="tablePagination()"
      >
        <template #bodyCell="{ column, record, text }">
          <span v-if="['id', 'source', 'destination', 'alert'].includes(String(column.key))" class="mono">{{
            text
          }}</span>
          <span v-else-if="['start', 'observed', 'stored'].includes(String(column.key))" class="tabular">{{
            text
          }}</span>
          <StatusTag
            v-else-if="column.key === 'retention'"
            :value="text"
            :tone="statusTone(retentionTones, record.retention)"
          />
          <span v-else-if="column.key === 'actions'" class="row-actions">
            <a-button
              type="link"
              size="small"
              :disabled="record.retention === '仅元数据'"
              @click="message.success('本地示例：打开逐包查看。')"
              >逐包查看</a-button
            >
            <a-button
              type="link"
              size="small"
              :disabled="record.retention === '仅元数据'"
              @click="
                message.success(
                  record.retention === '完整'
                    ? '本地示例：已创建完整会话下载。'
                    : '本地示例：已创建下载，文件标记为按策略截断。',
                )
              "
              >下载</a-button
            >
          </span>
        </template>
      </a-table>
    </section>
  </template>
</template>

<style scoped>
.traffic-policy-now {
  color: var(--muted);
  font-size: 12px;
}
.traffic-policy-edit {
  margin-left: var(--related-gap);
}
.traffic-filter {
  grid-template-columns: minmax(150px, 0.8fr) repeat(2, minmax(180px, 1.2fr)) minmax(150px, 0.8fr) auto;
}
@media (max-width: 1180px) {
  .traffic-filter {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
