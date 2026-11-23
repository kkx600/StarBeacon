<script setup lang="ts">
import { computed, ref } from 'vue';
import { PauseCircleOutlined, PlayCircleOutlined, CheckOutlined, CloseOutlined } from '@ant-design/icons-vue';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import type { MetricSpec, PageSpec, PreviewState } from '../models';
import PageHeader from '../components/PageHeader.vue';
import MetricBar from '../components/MetricBar.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import { responseTones } from '../data/statuses';
import StatePanel from '../components/StatePanel.vue';
import HelpNote from '../components/HelpNote.vue';
import { automationLevel } from '../composables/systemSettings';

// AI 值守：集中查看 AI 正在研判什么、给出了哪些处置方案、哪些待确认，并可一键暂停自动处置。
// 自动化级别属于系统设置，本页只读显示。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const message = useFeedback();

const paused = ref(false);

interface Proposal {
  id: string;
  alert: string;
  verdict: string;
  confidence: number;
  action: string;
  channel: string;
  scope: string;
  deadline: string;
  status: string;
}
const proposals = ref<Proposal[]>([
  {
    id: 'AIOPS-0001',
    alert: 'HTTP 可疑管理路径访问',
    verdict: '真实攻击',
    confidence: 0.94,
    action: '封禁源 IP 2 小时',
    channel: '防火墙插件 · 总部边界防火墙',
    scope: '198.51.100.24',
    deadline: '剩余 12 分钟',
    status: '待确认',
  },
  {
    id: 'AIOPS-0002',
    alert: 'DNS 异常外连查询',
    verdict: '真实攻击',
    confidence: 0.91,
    action: '旁路阻断当前连接，并封禁目的域名 24 小时',
    channel: '旁路阻断 + 防火墙插件',
    scope: '10.20.1.16 → 203.0.113.9',
    deadline: '剩余 9 分钟',
    status: '待确认',
  },
  {
    id: 'AIOPS-0003',
    alert: '疑似凭据暴力尝试',
    verdict: '可疑',
    confidence: 0.62,
    action: '通知资产负责人并继续观察 30 分钟',
    channel: '通知',
    scope: '10.20.1.17',
    deadline: '剩余 26 分钟',
    status: '待确认',
  },
  {
    id: 'AIOPS-0004',
    alert: 'SMB 横向访问线索',
    verdict: '真实攻击',
    confidence: 0.88,
    action: '隔离主机（EDR）',
    channel: 'EDR 插件 · 终端防护',
    scope: '10.20.1.19',
    deadline: '剩余 4 分钟',
    status: '待确认',
  },
  {
    id: 'AIOPS-0005',
    alert: 'TLS 异常证书链',
    verdict: '误报',
    confidence: 0.83,
    action: '关闭告警并记录原因',
    channel: '无设备动作',
    scope: '10.20.1.18',
    deadline: '—',
    status: '待确认',
  },
  {
    id: 'AIOPS-0006',
    alert: '高频端口探测',
    verdict: '真实攻击',
    confidence: 0.97,
    action: '封禁源 IP 24 小时',
    channel: '防火墙插件 · 总部边界防火墙',
    scope: '198.51.100.33',
    deadline: '剩余 18 分钟',
    status: '待确认',
  },
]);
const columns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 116 },
  { title: '告警', dataIndex: 'alert', key: 'alert', ellipsis: true },
  { title: 'AI 结论', dataIndex: 'verdict', key: 'verdict', width: 132 },
  { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 84 },
  { title: '建议处置', dataIndex: 'action', key: 'action', ellipsis: true },
  { title: '执行通道', dataIndex: 'channel', key: 'channel', width: 196, ellipsis: true },
  { title: '确认时限', dataIndex: 'deadline', key: 'deadline', width: 110 },
  { title: '操作', key: 'actions', width: 208, fixed: 'right' as const },
];

// 处置流水：AI 与值班员最近做过的事，和待确认的方案共用同一张表。
const journal = [
  {
    id: 'AIOPS-0001',
    time: '2026-09-30 09:42:31',
    event: '生成处置方案',
    target: '198.51.100.24',
    result: '待确认',
    note: '研判 8.1 秒，结论真实攻击',
  },
  {
    id: 'AIOPS-0098',
    time: '2026-09-30 09:40:02',
    event: '到期解除封禁',
    target: '198.51.100.61',
    result: '已完成',
    note: '回读确认规则已删除',
  },
  {
    id: 'AIOPS-0097',
    time: '2026-09-30 09:36:48',
    event: '旁路阻断',
    target: '10.20.1.44 → 203.0.113.80:443',
    result: '已完成',
    note: '3 秒内没有再出现该连接的流量',
  },
  {
    id: 'AIOPS-0096',
    time: '2026-09-30 09:31:15',
    event: '保护名单拦截',
    target: '10.20.0.1',
    result: '未执行',
    note: '目标属于管理地址',
  },
  {
    id: 'AIOPS-0095',
    time: '2026-09-30 09:24:10',
    event: '人工驳回',
    target: '198.51.100.40',
    result: '已驳回',
    note: '授权扫描，已记为误判样本',
  },
];
const journalColumns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 116 },
  { title: '时间', dataIndex: 'time', key: 'time', width: 160 },
  { title: '动作', dataIndex: 'event', key: 'event', width: 130 },
  { title: '对象', dataIndex: 'target', key: 'target', width: 260, ellipsis: true },
  { title: '结果', dataIndex: 'result', key: 'result', width: 104 },
  { title: '说明', dataIndex: 'note', key: 'note', ellipsis: true },
];
const verdictTones = { 真实攻击: 'danger', 误报: 'neutral', 可疑: 'warning', 证据不足: 'warning' } as const;
const view = ref<'待确认' | '处置流水'>('待确认');

const metrics = computed<MetricSpec[]>(() => [
  { label: '今日 AI 研判', value: props.state === 'empty' ? '0' : '1,248', note: '平均 8.4 秒' },
  { label: '待确认', value: String(pending.value.length), tone: 'warning' },
  { label: '已执行处置', value: props.state === 'empty' ? '0' : '14' },
  { label: '误判纠正', value: props.state === 'empty' ? '0' : '2' },
  { label: '保护名单拦截', value: props.state === 'empty' ? '0' : '5' },
]);
const pending = computed(() =>
  props.state === 'empty' ? [] : proposals.value.filter(item => item.status === '待确认'),
);

const detail = ref<Proposal>();
function decide(item: Proposal, approve: boolean) {
  item.status = approve ? '已确认' : '已驳回';
  detail.value = undefined;
  message.success(approve ? '已确认，原型只更新本地状态，不下发设备任务。' : '已驳回，并作为误判样本记录。');
}
function togglePause() {
  paused.value = !paused.value;
  message.warning(paused.value ? '自动处置已暂停，AI 仍会研判并给出方案。' : '自动处置已恢复。');
}
</script>

<template>
  <PageHeader :title="page.title" :description="page.description">
    <a-space wrap :size="16">
      <span class="aiops-level-now">
        自动化级别：{{ automationLevel }}
        <router-link class="aiops-level-edit" :to="{ path: '/page/system-settings', query: { section: 'automation' } }"
          >修改</router-link
        >
      </span>
      <a-button :danger="!paused" @click="togglePause">
        <PlayCircleOutlined v-if="paused" /><PauseCircleOutlined v-else />{{ paused ? '恢复自动处置' : '暂停自动处置' }}
      </a-button>
    </a-space>
  </PageHeader>
  <HelpNote message="保护名单、限时和可撤销在每一级自动化下都生效。" />
  <HelpNote message="本页为合成示例，不调用模型，也不向设备下发任务。" />

  <StatePanel v-if="state === 'loading' || state === 'error'" :state="state" @action="emit('state', 'data')" />
  <template v-else>
    <a-alert
      v-if="paused"
      class="page-notice"
      type="warning"
      show-icon
      message="自动处置已暂停：AI 继续研判并生成方案，但不会自动执行任何设备动作。"
    />
    <MetricBar :items="metrics" />

    <section class="panel table-panel">
      <div class="table-toolbar">
        <div><a-segmented v-model:value="view" :options="['待确认', '处置流水']" aria-label="查看内容" /></div>
      </div>
      <template v-if="view === '待确认'">
        <StatePanel
          v-if="!pending.length"
          state="empty"
          title="没有待确认的方案"
          description="AI 给出的处置方案会出现在这里。"
          action="查看处置流水"
          @action="view = '处置流水'"
        />
        <a-table
          v-else
          :columns="columns"
          :data-source="pending"
          row-key="id"
          size="small"
          :scroll="{ x: 1170 }"
          :pagination="tablePagination()"
        >
          <template #bodyCell="{ column, record, text }">
            <span v-if="column.key === 'id'" class="mono">{{ text }}</span>
            <button v-else-if="column.key === 'alert'" class="record-link" @click="detail = record as Proposal">
              {{ text }}
            </button>
            <StatusTag
              v-else-if="column.key === 'verdict'"
              :value="text"
              :tone="statusTone(verdictTones, record.verdict)"
            />
            <span v-else-if="column.key === 'confidence'" class="tabular">{{ Math.round(Number(text) * 100) }}%</span>
            <span v-else-if="column.key === 'actions'" class="row-actions">
              <a-button type="link" size="small" @click="decide(record as Proposal, true)"
                ><CheckOutlined />确认执行</a-button
              >
              <a-button type="link" size="small" @click="decide(record as Proposal, false)"
                ><CloseOutlined />驳回</a-button
              >
              <a-button type="link" size="small" @click="detail = record as Proposal">依据</a-button>
            </span>
          </template>
        </a-table>
      </template>
      <a-table
        v-else
        :columns="journalColumns"
        :data-source="state === 'empty' ? [] : journal"
        row-key="id"
        size="small"
        :scroll="{ x: 1170 }"
        :pagination="tablePagination()"
      >
        <template #bodyCell="{ column, record, text }">
          <span v-if="column.key === 'id' || column.key === 'target'" class="mono">{{ text }}</span>
          <span v-else-if="column.key === 'time'" class="tabular">{{ text }}</span>
          <StatusTag
            v-else-if="column.key === 'result'"
            :value="text"
            :tone="statusTone(responseTones, record.result)"
          />
        </template>
      </a-table>
    </section>
  </template>

  <a-modal :open="!!detail" :title="`处置依据 · ${detail?.id ?? ''}`" :width="760" @cancel="detail = undefined">
    <template v-if="detail">
      <a-descriptions bordered size="small" :column="2">
        <a-descriptions-item label="告警">{{ detail.alert }}</a-descriptions-item>
        <a-descriptions-item label="AI 结论"
          >{{ detail.verdict }}（{{ Math.round(detail.confidence * 100) }}%）</a-descriptions-item
        >
        <a-descriptions-item label="建议处置" :span="2">{{ detail.action }}</a-descriptions-item>
        <a-descriptions-item label="执行通道">{{ detail.channel }}</a-descriptions-item>
        <a-descriptions-item label="影响范围">{{ detail.scope }}</a-descriptions-item>
      </a-descriptions>
      <h3 class="aiops-section">研判依据</h3>
      <ul class="aiops-evidence">
        <li><b>检测</b>规则命中 3 次，同一来源 10 分钟内访问 14 个管理路径。</li>
        <li><b>会话</b>握手完整，服务端返回 200 且响应体含登录表单。</li>
        <li><b>情报</b>来源地址在两个情报源中标记为扫描器，最近 7 天内有效。</li>
        <li><b>资产</b>目标属于“核心业务”资产组，重要性高。</li>
        <li><b>缺失</b>没有终端或应用日志，无法判断是否利用成功。</li>
      </ul>
      <h3 class="aiops-section">执行前核对</h3>
      <ul class="aiops-evidence">
        <li><b>保护名单</b>目标不在保护名单内。</li>
        <li><b>回退</b>到期自动解除；也可以在响应动作里手动撤销。</li>
        <li><b>验证</b>执行后回读设备配置，并观察 5 分钟内是否仍有该来源的流量。</li>
      </ul>
    </template>
    <template #footer>
      <a-button @click="detail && decide(detail, false)">驳回</a-button>
      <a-button type="primary" @click="detail && decide(detail, true)">确认执行</a-button>
    </template>
  </a-modal>
</template>

<style scoped>
.aiops-level-now {
  color: var(--muted);
  font-size: 12px;
}
.aiops-level-edit {
  margin-left: var(--related-gap);
}
.aiops-section {
  margin: var(--panel-inset) 0 var(--related-gap);
  font-size: 14px;
  font-weight: 600;
}
.aiops-evidence {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13px;
  line-height: 1.7;
}
.aiops-evidence b {
  display: inline-block;
  min-width: 64px;
  color: var(--muted);
  font-weight: 500;
}
</style>
