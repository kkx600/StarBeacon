<script setup lang="ts">
import TimeRangeField from '../../../web/packages/shared/src/components/TimeRangeField.vue';
import ListFilters from '../../../web/packages/shared/src/components/ListFilters.vue';
import HelpNote from './HelpNote.vue';
import { computed, ref, shallowRef, watch } from 'vue';
import { useRoute } from 'vue-router';
import type { PreviewState } from '../models';
import PageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';
import DiscoveryPanel from '../../../web/packages/shared/src/components/DiscoveryPanel.vue';
import InventoryForm from '../../../web/platform/src/features/inventory/InventoryForm.vue';
import type { InventoryData } from '../../../web/platform/src/features/inventory/inventory';
import type { DiscoveryResult, DiscoveryAddress } from '../../../web/packages/shared/src/discovery';
const props = defineProps<{ state: PreviewState }>(),
  emit = defineEmits<{ state: [value: PreviewState] }>(),
  route = useRoute();
const start = ref('2026-10-18T08:00:00'),
  end = ref('2026-10-18T09:00:00');
const query = {
  network_id: 'network_example',
  network_revision: 3,
  sensor_id: 'probe_example',
  registration_id: 'registration_example',
  prefix: '192.0.2.0/24',
  start: '2026-10-18T00:00:00Z',
  end: '2026-10-18T01:00:00Z',
};
const sample = {
  event_id: 'event_example_first',
  timestamp: '2026-10-18T00:05:12.123456789Z',
  observed_at: '2026-10-18T00:05:13Z',
  generation_id: 'generation_example',
  sequence: '18446744073709551614',
  raw_sha256: 'a'.repeat(64),
  flow_id: '18446744073709551615',
  side: 'source' as const,
  source: { ip: '192.0.2.10', port: 52134, mac: '02:00:00:00:00:01' },
  destination: { ip: '198.51.100.20', port: 443, mac: '02:00:00:00:00:02' },
};
const original: DiscoveryResult = {
  schema_version: '1.0',
  query,
  scope: {
    network_id: query.network_id,
    network_revision: 3,
    network_name: '办公区网段（示例）',
    network_domain: 'office',
    network_prefix: query.prefix,
    sensor_id: query.sensor_id,
    sensor_name: '办公区探针（示例）',
    registration_id: query.registration_id,
  },
  queried_at: '2026-10-18T01:00:00Z',
  source_excluded: '0',
  destination_excluded: '0',
  partition_status: 'available',
  addresses: [
    {
      ip: '192.0.2.10',
      source_records: '1528',
      destination_records: '362',
      first: sample,
      last: {
        ...sample,
        event_id: 'event_example_last',
        timestamp: '2026-10-18T00:58:20.987654321Z',
        observed_at: '2026-10-18T00:58:21Z',
        sequence: '18446744073709551615',
        side: 'destination',
        source: { ip: '198.51.100.20', port: 443, mac: '02:00:00:00:00:02' },
        destination: { ip: '192.0.2.10', port: 52134, mac: '02:00:00:00:00:01' },
      },
    },
  ],
};
const result = computed(() =>
  ['empty', 'loading', 'error'].includes(props.state)
    ? {
        ...original,
        addresses: [],
        partition_status: route.query.result === 'absent' ? ('absent' as const) : ('available' as const),
      }
    : route.query.result === 'large'
      ? {
          ...original,
          addresses: original.addresses.map(row => ({
            ...row,
            source_records: '9223372036854775807',
            destination_records: '9223372036854775807',
          })),
        }
      : original,
);
const draft = shallowRef<InventoryData | null>(null),
  saved = shallowRef(false);
function register(row: DiscoveryAddress) {
  draft.value = {
    name: '',
    active: true,
    description: '',
    owner: '',
    network_domain: 'office',
    group_id: '',
    criticality: 'normal',
    interfaces: [{ name: '', mac: '', ips: [row.ip] }],
  };
}
watch(
  () => props.state,
  () => {
    draft.value = null;
    saved.value = false;
    if (props.state === 'action') register(original.addresses[0]!);
  },
  { immediate: true },
);
</script>
<template>
  <PageHeader
    :help-entries="helpEntries"
    title="资产被动发现"
    description="按探针与网段核对流量地址观测，确认身份后登记资产。"
    ><router-link to="/page/assets"><a-button>资产目录</a-button></router-link></PageHeader
  >
  <HelpNote
    message="本页面使用合成示例，复用工程观测与登记组件。单次查询最多返回 512 个地址，每租户每分钟最多 6 次查询。地址计数不等于设备数或独立会话数，也不证明完整捕获覆盖；原型不查询流量或登记实际资产。"
  />
  <a-alert v-if="saved" type="success" show-icon message="示例资产已登记。" class="section-gap" />
  <a-form layout="horizontal" @finish="emit('state', 'data')">
    <ListFilters label="被动发现筛选" :columns="3">
      <TimeRangeField
        id-prefix="preview-discovery"
        v-model:start="start"
        v-model:end="end"
        required
        end-hint="结束时刻不包含在查询内，窗口最多 24 小时。"
      />
      <a-form-item label="探针" html-for="preview-discovery-sensor" required
        ><a-select
          id="preview-discovery-sensor"
          default-value="probe_example"
          :options="[{ value: 'probe_example', label: '办公区探针（示例）' }]" /></a-form-item
      ><a-form-item label="网段" html-for="preview-discovery-network" required
        ><a-select
          id="preview-discovery-network"
          default-value="network_example"
          :options="[{ value: 'network_example', label: '办公区网段（示例） · 192.0.2.0/24' }]" /></a-form-item
      ><a-form-item
        label="查询前缀"
        html-for="preview-discovery-prefix"
        required
        extra="可缩小到已选网段的子网段，使用标准 CIDR。"
        ><a-input id="preview-discovery-prefix" default-value="192.0.2.0/24"
      /></a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="state === 'loading'">执行发现</a-button>
        <a-button @click="emit('state', 'data')">刷新目录</a-button>
      </template>
    </ListFilters>
  </a-form>
  <DiscoveryPanel
    :result="result"
    :pending="state === 'loading'"
    :error="
      state === 'error'
        ? route.query.result === 'limit'
          ? '观测地址超过单次 512 个的上限，请缩短时间或缩小地址前缀。'
          : '未能完整核对流量观测，本次不提供部分结果。'
        : ''
    "
    attempted
    can-register
    :initial-i-p="state === 'detail' ? '192.0.2.10' : undefined"
    @retry="emit('state', 'data')"
    @register="register"
  />
  <InventoryForm
    v-if="draft"
    kind="assets"
    :record="null"
    :draft="draft"
    :groups="[]"
    :pending="false"
    error=""
    @close="draft = null"
    @save="
      draft = null;
      saved = true;
      emit('state', 'data');
    "
  />
</template>
