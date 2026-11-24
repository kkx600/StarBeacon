<script setup lang="ts">
import { shallowRef, watch } from 'vue';
import { Modal as AModal } from 'ant-design-vue';
import StatePanel from './StatePanel.vue';
import PageHelp from './PageHelp.vue';
import ListTable from './ListTable.vue';
import MetricBar from './MetricBar.vue';
import { tablePagination } from '../pagination';
import { discoveryCount, discoveryEndpoint, type DiscoveryResult, type DiscoveryAddress } from '../discovery';
import { formatTime } from '../types';
const props = defineProps<{
  result: DiscoveryResult | null;
  pending: boolean;
  error: string;
  attempted: boolean;
  canRegister?: boolean;
  initialIP?: string;
}>();
const emit = defineEmits<{ retry: []; register: [row: DiscoveryAddress, result: DiscoveryResult] }>();
const selected = shallowRef<DiscoveryAddress | null>(null);
watch(
  () => [props.result, props.initialIP],
  () => {
    selected.value = props.result?.addresses.find(row => row.ip === props.initialIP) ?? null;
  },
  { immediate: true },
);
const columns = [
  { title: '观测 IP', key: 'ip', width: 190, className: 'technical', fixed: 'left' as const },
  { title: '源方向流记录', key: 'source', width: 194, ellipsis: true },
  { title: '目的方向流记录', key: 'destination', width: 194, ellipsis: true },
  { title: '首次记录时间', key: 'first', width: 170 },
  { title: '末次记录时间', key: 'last', width: 170 },
  { title: '操作', key: 'actions', width: 150, fixed: 'right' as const },
];
</script>
<template>
  <section class="panel discovery-panel">
    <div class="table-toolbar">
      <div>
        <h2>地址观测</h2>
        <PageHelp title="地址观测">
          <p>按已有流记录发现地址，源、目的方向分别计数。单次查询最多返回 512 个地址。</p>
          <p>查询窗口不包含结束时刻。组播、未指定及全局广播方向单独计数。</p>
        </PageHelp>
      </div>
    </div>
    <div v-if="result && !pending && !error" class="discovery-summary">
      <strong>{{ result.scope.network_name }} · {{ result.scope.network_domain }}</strong
      ><span>{{ result.scope.sensor_name }} · {{ result.query.prefix }}</span
      ><span
        >查询窗口：{{ formatTime(result.query.start) }} 至 {{ formatTime(result.query.end) }}（结束时刻不包含）</span
      >
    </div>
    <MetricBar
      v-if="result && !pending && !error"
      embedded
      :items="[
        { label: '观测地址', value: result.addresses.length },
        { label: '排除源方向', value: discoveryCount(result.source_excluded) },
        { label: '排除目的方向', value: discoveryCount(result.destination_excluded) },
      ]"
    />
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!result || result.addresses.length === 0"
      :description="
        !attempted
          ? '选择探针、网段和时间窗口后执行发现。'
          : result?.partition_status === 'absent'
            ? '平台尚无可查询的流量索引，请核对采集、索引写入与保留状态。'
            : '当前范围没有地址观测记录，请核对探针、时间窗口和采集覆盖。'
      "
      @retry="emit('retry')"
    >
      <ListTable
        :columns="columns"
        :data-source="result?.addresses ?? []"
        row-key="ip"
        :pagination="tablePagination()"
        :scroll="{ x: 1068 }"
      >
        <template #bodyCell="{ column, record }"
          ><button
            v-if="column.key === 'ip'"
            class="record-link technical"
            type="button"
            :title="record.ip"
            @click="selected = record"
          >
            {{ record.ip }}</button
          ><span v-else-if="column.key === 'source'" :title="discoveryCount(record.source_records)">{{
            discoveryCount(record.source_records)
          }}</span
          ><span v-else-if="column.key === 'destination'" :title="discoveryCount(record.destination_records)">{{
            discoveryCount(record.destination_records)
          }}</span
          ><time v-else-if="column.key === 'first'" :datetime="record.first.timestamp">{{
            formatTime(record.first.timestamp)
          }}</time
          ><time v-else-if="column.key === 'last'" :datetime="record.last.timestamp">{{
            formatTime(record.last.timestamp)
          }}</time>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button size="small" type="link" @click="selected = record">证据</a-button
            ><a-button v-if="canRegister && result" size="small" type="link" @click="emit('register', record, result)"
              >登记资产</a-button
            >
          </div></template
        >
      </ListTable>
    </StatePanel>
  </section>
  <a-modal v-if="selected && result" open title="地址观测证据" :width="860" :footer="null" @cancel="selected = null">
    <a-alert
      type="info"
      show-icon
      message="IP 与 MAC 来自流记录端点；网关、NAT、DHCP 和镜像位置会影响观测，不能据此认定资产身份或接口归属。"
      class="section-gap"
    />
    <dl class="discovery-facts">
      <dt>观测地址</dt>
      <dd>{{ selected.ip }}</dd>
      <dt>探针 / 注册标识</dt>
      <dd>{{ result.scope.sensor_name }} / {{ result.scope.registration_id }}</dd>
      <dt>网络域 / 网段修订</dt>
      <dd>{{ result.scope.network_domain }} / {{ result.scope.network_name }} · {{ result.scope.network_revision }}</dd>
    </dl>
    <section v-for="(sample, index) in [selected.first, selected.last]" :key="index" class="discovery-evidence">
      <h3>{{ index === 0 ? '首次记录' : '末次记录' }} · {{ sample.side === 'source' ? '源方向' : '目的方向' }}</h3>
      <dl class="discovery-facts">
        <dt>事件时间</dt>
        <dd>
          <time :datetime="sample.timestamp">{{ formatTime(sample.timestamp, { fraction: 'source' }) }}</time>
        </dd>
        <dt>采集器读取时间</dt>
        <dd>
          <time :datetime="sample.observed_at">{{ formatTime(sample.observed_at, { fraction: 'source' }) }}</time>
        </dd>
        <dt>源端点</dt>
        <dd>{{ discoveryEndpoint(sample.source) }} · MAC {{ sample.source.mac || '未记录' }}</dd>
        <dt>目的端点</dt>
        <dd>{{ discoveryEndpoint(sample.destination) }} · MAC {{ sample.destination.mac || '未记录' }}</dd>
        <dt>事件 / 流标识</dt>
        <dd>{{ sample.event_id }} / {{ sample.flow_id }}</dd>
        <dt>源代次 / 序号</dt>
        <dd>{{ sample.generation_id }} / {{ sample.sequence }}</dd>
        <dt>原始记录 SHA-256</dt>
        <dd>
          <code>{{ sample.raw_sha256 }}</code>
        </dd>
      </dl>
    </section>
    <div class="filter-actions">
      <a-button
        v-if="canRegister"
        type="primary"
        @click="
          emit('register', selected, result);
          selected = null;
        "
        >登记资产</a-button
      ><a-button @click="selected = null">关闭</a-button>
    </div>
  </a-modal>
</template>
<style scoped>
.filter-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--related-gap);
}
.discovery-summary {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 0 var(--panel-inset) var(--section-gap);
  color: var(--muted);
  overflow-wrap: anywhere;
}
.discovery-summary strong {
  color: var(--text);
}
.discovery-panel {
  min-width: 0;
  overflow: hidden;
}
.discovery-facts {
  display: grid;
  grid-template-columns: 155px minmax(0, 1fr);
  gap: 8px 12px;
  margin: 12px 0;
}
.discovery-facts dt {
  color: var(--muted);
}
.discovery-facts dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.discovery-evidence {
  border-top: 1px solid var(--line);
  padding-top: 12px;
  margin-top: 12px;
}
.discovery-evidence h3 {
  margin: 0;
  font-size: 14px;
}
</style>
