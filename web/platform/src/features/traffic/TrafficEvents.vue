<script setup lang="ts">
import { shallowRef, watch } from 'vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import TrafficFilters from './TrafficFilters.vue';
import TrafficTable from './TrafficTable.vue';
import TrafficDetail from './TrafficDetail.vue';
import { useTraffic } from './useTraffic';
import type { TrafficQuery, TrafficRecord } from './traffic';
import { session } from '../../session';
import SavedSearchTools from '../search/SavedSearchTools.vue';
import SearchExportButton from '../search/SearchExportButton.vue';
import type { SavedDefinition, SavedResolution } from '../search/savedSearch';
const title = usePageTitle('协议流量');
const { result, pending, error, appliedQuery, range, definition, fixed, search, page, refresh, applyQuery } =
    useTraffic(),
  selected = shallowRef<TrafficRecord | null>(null),
  applied = shallowRef<SavedDefinition>();
function apply(value: SavedResolution) {
  applied.value = value.definition;
  applyQuery(
    value.query as TrafficQuery,
    value.definition.window.mode === 'absolute' ? 0 : value.definition.window.hours,
  );
}
watch(
  () => [session.current.value?.tenant_id, session.current.value?.id, session.current.value?.role].join('/'),
  () => {
    selected.value = null;
    applied.value = undefined;
  },
);
</script>
<template>
  <PageHeader :title="title" description="检索协议事件与会话摘要。记录数不等于独立会话数或数据包数。">
    <SavedSearchTools dataset="context" :current="definition" :disabled="pending" @apply="apply" /><SearchExportButton
      dataset="context"
      :query="appliedQuery"
      :disabled="pending || !!error"
    /><a-button :loading="pending" @click="refresh">刷新</a-button>
  </PageHeader>
  <MetricBar
    v-if="range && !error"
    :items="[
      { label: '匹配记录', value: result.total },
      { label: '检索窗口', value: `${formatTime(range.start)} — ${formatTime(range.end)}` },
    ]"
  />
  <TrafficFilters
    :key="[session.current.value?.tenant_id, session.current.value?.id, session.current.value?.role].join('/')"
    :pending="pending"
    :applied="applied"
    :fixed="fixed"
    @search="search"
  />
  <a-alert
    v-if="result.total > 10000"
    type="info"
    message="当前列表最多浏览前 10,000 条，请缩小时间范围或增加检索条件。"
    show-icon
    class="section-gap"
  />
  <section class="panel">
    <div class="panel-header">
      <h2>流量记录</h2>
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!result.items.length"
      description="当前条件下没有协议记录。请核对探针采集状态、协议日志配置、时间范围和检索条件。"
      @retry="refresh"
      ><TrafficTable :result="result" @view="selected = $event"
    /></StatePanel>
    <ListPager
      :page="result.page"
      :page-size="result.page_size"
      :total="error ? 0 : Math.min(result.total, 10000)"
      :disabled="pending || !!error"
      @change="page"
    />
  </section>
  <TrafficDetail :record="selected" @close="selected = null" />
</template>
