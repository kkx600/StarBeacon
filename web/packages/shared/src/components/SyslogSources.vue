<script setup lang="ts">
import { statusTerms } from '../terms';
import { formatNumber } from '../utils/format';
import { computed, shallowRef, watch, onScopeDispose } from 'vue';
import { Modal as AModal, Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import { sourceStates, type SyslogSource } from '../syslog';
import { formatTime } from '../types';
import { tablePagination } from '../pagination';
import { statusTone, type StatusToneMap } from '../statusTones';
import ListTable from './ListTable.vue';
import StatusTag from './StatusTag.vue';
const props = defineProps<{ items: readonly SyslogSource[]; local?: boolean; paginate?: boolean; detailID?: string }>(),
  emit = defineEmits<{ close: [] }>(),
  selected = shallowRef<SyslogSource | null>(null);
watch(
  () => props.detailID,
  id => {
    selected.value = props.items.find(v => v.source_id === id) ?? null;
  },
  { immediate: true },
);
watch(
  () => props.items,
  items => {
    if (selected.value)
      selected.value =
        items.find(v => v.source_id === selected.value?.source_id && v.sensor_id === selected.value?.sensor_id) ?? null;
  },
);
const now = shallowRef(Date.now()),
  timer = setInterval(() => {
    now.value = Date.now();
  }, 5000);
onScopeDispose(() => clearInterval(timer));
function stale(v: SyslogSource) {
  return (
    v.observation === 'stale' ||
    Date.parse(v.observed_at) < now.value - 35000 ||
    Date.parse(v.observed_at) > now.value + 30000
  );
}
const rows = computed(() => [...props.items]),
  columns = computed(() => [
    { title: '来源编号', dataIndex: 'source_id', width: 144, className: 'technical', ellipsis: true },
    { title: '日志来源', dataIndex: 'source_name', width: 156, ellipsis: true },
    ...(!props.local
      ? [
          { title: '探针编号', dataIndex: 'sensor_id', width: 144, className: 'technical', ellipsis: true },
          { title: '接入探针', dataIndex: 'sensor_name', width: 146, ellipsis: true },
        ]
      : []),
    { title: '网络域', dataIndex: 'network_domain', width: 122, ellipsis: true },
    { title: '协议', key: 'transport', width: 122 },
    { title: '接收状态', key: 'state', width: 132 },
    { title: '持久保存 / 接收', key: 'count', width: 180, ellipsis: true },
    { title: '最近保存', key: 'time', width: 170 },
    { title: '操作', key: 'action', width: 68, fixed: 'right' as const },
  ]);
function close() {
  selected.value = null;
  emit('close');
}
const sourceTones: StatusToneMap = {
  starting: 'info',
  listening: 'success',
  unavailable: statusTerms.异常,
  degraded: statusTerms.异常,
  stopped: 'neutral',
};
function condition(v: SyslogSource) {
  if (v.sensor_status === 'disabled') return { value: '探针停用', tone: statusTerms.停用 } as const;
  if (v.sensor_status === 'offline') return { value: '探针离线', tone: statusTerms.离线 } as const;
  if (stale(v)) return { value: '观测已过期', tone: statusTerms.已过期 } as const;
  return { value: sourceStates[v.state] ?? '接收状态未知', tone: statusTone(sourceTones, v.state) };
}
</script>
<template>
  <ListTable
    :columns="columns"
    :data-source="rows"
    :row-key="(row: SyslogSource) => (row.sensor_id ?? 'local') + '/' + row.source_id"
    :pagination="local || paginate ? tablePagination() : false"
    :scroll="{ x: local ? 1094 : 1384 }"
    ><template #bodyCell="{ column, record }"
      ><template v-if="column.key === 'transport'"
        >{{ record.transport.toUpperCase() }} · {{ record.format.toUpperCase() }}</template
      ><StatusTag v-else-if="column.key === 'state'" v-bind="condition(record)" />
      <template v-else-if="column.key === 'count'"
        ><span class="technical"
          >{{ formatNumber(BigInt(record.persisted)) }} / {{ formatNumber(BigInt(record.received)) }}</span
        ></template
      ><template v-else-if="column.key === 'time'">{{
        record.last_persisted_at ? formatTime(record.last_persisted_at) : '尚无保存记录'
      }}</template
      ><a-button v-else-if="column.key === 'action'" size="small" type="link" @click="selected = record"
        >查看</a-button
      ></template
    ></ListTable
  >
  <a-modal title="Syslog 来源详情" :open="selected !== null" :width="720" destroy-on-close @cancel="close"
    ><template v-if="selected"
      ><a-descriptions bordered :column="1" size="small"
        ><a-descriptions-item label="来源">{{ selected.source_name }} / {{ selected.source_id }}</a-descriptions-item
        ><a-descriptions-item v-if="!local" label="接入探针"
          >{{ selected.sensor_name }} / {{ selected.sensor_id }}</a-descriptions-item
        ><a-descriptions-item label="网络域">{{ selected.network_domain }}</a-descriptions-item
        ><a-descriptions-item label="接收状态"><StatusTag v-bind="condition(selected)" /></a-descriptions-item
        ><a-descriptions-item label="传输 / 格式"
          >{{ selected.transport.toUpperCase() }} / {{ selected.format.toUpperCase() }}</a-descriptions-item
        ><a-descriptions-item label="来源身份">{{
          selected.identity_quality === 'certificate' ? '客户端证书与指纹验证' : '仅按来源网段限制，设备身份待验证'
        }}</a-descriptions-item
        ><a-descriptions-item label="来源时间策略">{{
          selected.format === 'rfc3164'
            ? selected.timezone + ' · 按接收时间选择最近年份'
            : '使用原文时区，缺失时间单独标记'
        }}</a-descriptions-item
        ><a-descriptions-item label="消息上限">{{ formatNumber(selected.max_message_bytes) }} B</a-descriptions-item
        ><a-descriptions-item label="本次运行计数"
          >接收 {{ selected.received }} · 持久保存 {{ selected.persisted }} · 接收后未保存 {{ selected.dropped }} · 拒绝
          {{ selected.rejected }} · 分帧错误 {{ selected.framing_errors }}</a-descriptions-item
        ><a-descriptions-item label="运行开始">{{ formatTime(selected.started_at) }}</a-descriptions-item
        ><a-descriptions-item label="观测时间">{{ formatTime(selected.observed_at) }}</a-descriptions-item
        ><a-descriptions-item label="配置 SHA-256"
          ><span class="technical digest">{{ selected.config_sha256 }}</span></a-descriptions-item
        ></a-descriptions
      >
      <p class="page-description section-gap">
        计数自本次接收器启动起累计，接收时间不等于原设备事件时间。{{
          selected.transport === 'udp'
            ? 'UDP 无交付确认，无法据此推算发送侧丢失率。'
            : '持久保存仅证明本地队列写入，不代表平台已完成索引。'
        }}
        来源配置通过采集器私有文件管理，变更后需受控重启。
      </p></template
    ><template #footer><a-button @click="close">关闭</a-button></template></a-modal
  >
</template>
<style scoped>
.digest {
  overflow-wrap: anywhere;
}
</style>
