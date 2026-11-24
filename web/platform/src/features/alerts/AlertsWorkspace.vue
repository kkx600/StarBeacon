<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('告警管理');
import { shallowRef, watch } from 'vue';
import type { Alert } from '@starbeacon/shared/types.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import AlertFilters from './AlertFilters.vue';
import AlertTable from './AlertTable.vue';
import AlertDetail from './AlertDetail.vue';
import { useAlerts } from './useAlerts';
import { session } from '../../session';
import SavedSearchTools from '../search/SavedSearchTools.vue';
import SearchExportButton from '../search/SearchExportButton.vue';
import type { SavedDefinition, SavedResolution } from '../search/savedSearch';
const props = defineProps<{ window?: { start?: string; end?: string }; advanced?: boolean }>();
const { result, pending, error, appliedQuery, inherited, range, definition, search, page, refresh, applyQuery } =
  useAlerts(props.window);
const selected = shallowRef<Alert | null>(null);
const applied = shallowRef<SavedDefinition>();
function apply(value: SavedResolution) {
  applied.value = value.definition;
  applyQuery(value.query, value.definition.window.mode === 'relative' ? value.definition.window.hours : 0);
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
  <PageHeader :title="pageTitle" description="检索已入库的原始检测事件，核对来源、时间和通信元数据。">
    <SavedSearchTools dataset="alerts" :current="definition" :disabled="pending" @apply="apply" />
    <SearchExportButton dataset="alerts" :query="appliedQuery" :disabled="pending || !!error" />
    <a-button :loading="pending" @click="refresh">刷新</a-button>
  </PageHeader>
  <AlertFilters
    :advanced="advanced"
    :key="[session.current.value?.tenant_id, session.current.value?.id, session.current.value?.role].join('/')"
    :pending="pending"
    :inherited="inherited"
    :applied="applied"
    @search="search"
  />
  <a-alert
    v-if="result.total > 10000"
    type="info"
    message="当前列表最多浏览前 10,000 条，请缩小时间范围或增加检索条件。"
    show-icon
    class="section-gap"
  />
  <section class="panel table-panel">
    <div class="table-toolbar">
      <div>
        <h2>告警列表</h2>
        <span class="muted">{{ formatTime(range.start) }} — {{ formatTime(range.end) }}</span>
      </div>
      <MetricBar v-if="!pending && !error" embedded :items="[{ label: '匹配告警', value: result.total }]" />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="result.items.length === 0"
      description="当前条件下没有告警，可调整时间范围或检索条件。"
      @retry="refresh"
      ><AlertTable :result="result" @view="selected = $event" @page="page"
    /></StatePanel>
  </section>
  <AlertDetail :alert="selected" @close="selected = null" />
</template>
