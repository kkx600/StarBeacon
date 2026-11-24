<script setup lang="ts">
import { formatNumber } from '../utils/format';
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue';
import { Modal as AModal, Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import type { ResponseConnector } from '../response';
import { responseStates, readyConnector } from '../response';
import { formatTime } from '../types';
import StatePanel from './StatePanel.vue';
import PageHelp from './PageHelp.vue';
import ListTable from './ListTable.vue';
import StatusTag from './StatusTag.vue';
import { tablePagination } from '../pagination';
import { statusTone, type StatusToneMap } from '../statusTones';
const props = defineProps<{ items: readonly ResponseConnector[]; detailID?: string }>();
const emit = defineEmits<{ close: [] }>();
const selected = shallowRef<ResponseConnector | null>(null);
watch(
  () => props.detailID,
  id => {
    selected.value = props.items.find(v => v.connector_id === id) ?? null;
  },
  { immediate: true },
);
watch(
  () => props.items,
  items => {
    if (selected.value) selected.value = items.find(v => v.connector_id === selected.value?.connector_id) ?? null;
  },
);
function close() {
  selected.value = null;
  emit('close');
}
const rows = computed(() => [...props.items]);
const columns = [
  { title: '连接器编号', dataIndex: 'connector_id', width: 146, className: 'technical', ellipsis: true },
  { title: '设备编号', dataIndex: 'device_id', width: 146, className: 'technical', ellipsis: true },
  { title: '接口版本', dataIndex: 'version', width: 160, ellipsis: true },
  { title: '状态', key: 'state', width: 140 },
  { title: '最长封禁', key: 'ttl', width: 110 },
  { title: '核验时间', key: 'time', width: 190 },
  { title: '操作', key: 'action', width: 68, fixed: 'right' as const },
];
const now = shallowRef(Date.now());
let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  timer = setInterval(() => {
    now.value = Date.now();
  }, 5000);
});
onScopeDispose(() => {
  if (timer) clearInterval(timer);
});
const tones: StatusToneMap = { ready: 'success', unavailable: 'danger' };
function condition(record: ResponseConnector) {
  if (record.status === 'ready' && !readyConnector(record, now.value))
    return { value: '观测已过期', tone: 'neutral' } as const;
  return { value: responseStates[record.status] ?? '状态待核查', tone: statusTone(tones, record.status) };
}
</script>
<template>
  <section class="panel">
    <div class="table-toolbar">
      <div>
        <h2>联动设备</h2>
        <PageHelp title="联动设备">
          <p>固定 HTTPS 管理地址和凭据引用由本机私有文件管理。</p>
          <p>设备身份与原生 TTL 核验后，平台管理员可通过此采集器提交限时联动任务。</p>
        </PageHelp>
      </div>
    </div>
    <StatePanel
      :empty="!items.length"
      description="尚未登记联动设备。请配置采集器的 HTTP 连接器文件，并核对设备接口版本与目标保护范围。"
      ><ListTable
        :columns="columns"
        :data-source="rows"
        row-key="connector_id"
        :pagination="tablePagination()"
        :scroll="{ x: 1080 }"
        ><template #bodyCell="{ column, record }"
          ><StatusTag v-if="column.key === 'state'" v-bind="condition(record)" />
          <template v-else-if="column.key === 'time'">{{
            record.observed_at === '0001-01-01T00:00:00Z' ? '尚未核验' : formatTime(record.observed_at)
          }}</template><template v-else-if="column.key === 'ttl'">{{ record.max_ttl_seconds }} 秒</template
          ><a-button v-else-if="column.key === 'action'" size="small" type="link" @click="selected = record"
            >查看</a-button
          ></template
        ></ListTable
      >
    </StatePanel>
  </section>
  <a-modal title="联动设备详情" :open="selected !== null" :width="660" :footer="null" @cancel="close"
    ><template v-if="selected"
      ><a-descriptions bordered :column="1" size="small"
        ><a-descriptions-item label="连接器 / 设备"
          >{{ selected.connector_id }} / {{ selected.device_id }}</a-descriptions-item
        ><a-descriptions-item label="接口版本">{{ selected.version }}</a-descriptions-item
        ><a-descriptions-item label="设备状态"><StatusTag v-bind="condition(selected)" /></a-descriptions-item
        ><a-descriptions-item label="配置 SHA-256"
          ><span class="technical" style="overflow-wrap: anywhere">{{
            selected.config_sha256
          }}</span></a-descriptions-item
        ><a-descriptions-item label="核验时间">{{
          selected.observed_at === '0001-01-01T00:00:00Z' ? '尚未核验' : formatTime(selected.observed_at)
        }}</a-descriptions-item
        ><a-descriptions-item label="最长封禁"
          >{{ formatNumber(selected.max_ttl_seconds) }} 秒</a-descriptions-item
        ></a-descriptions
      >
      <p class="page-description section-gap">
        就绪观测超过 35 秒需要重新核对。封禁、回读与解除由主控平台管理员提交签名任务；旁路探针自身不阻断流量。
      </p>
      <div class="filter-actions"><a-button @click="close">关闭</a-button></div></template
    ></a-modal
  >
</template>
