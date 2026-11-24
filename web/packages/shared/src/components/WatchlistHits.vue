<script setup lang="ts">
import { formatNumber } from '../utils/format';
import { computed, reactive, watch } from 'vue';
import StatePanel from './StatePanel.vue';
import ListFilters from './ListFilters.vue';
import ListPager from './ListPager.vue';
import ListTable from './ListTable.vue';
import PageHelp from './PageHelp.vue';
import StatusTag from './StatusTag.vue';
import TimeRangeField from './TimeRangeField.vue';
import WatchlistMatchCell from './WatchlistMatchCell.vue';
import { defaultPageSize } from '../pagination';
import { alertSeverityTones, statusTone } from '../statusTones';
import { localWatchlistTime, watchlistDailyHitCap, watchlistSeverities, type WatchlistHitPage } from '../watchlists';
import { formatTime } from '../types';
const props = withDefaults(
  defineProps<{
    listId: string;
    page: WatchlistHitPage;
    pending: boolean;
    error: string;
    loaded: boolean;
    pages: number;
    pageSize?: number;
  }>(),
  { pageSize: defaultPageSize },
);
const emit = defineEmits<{
  query: [start: string, end: string];
  next: [];
  previous: [];
  retry: [];
  'update:pageSize': [size: number];
}>();
// 默认窗口为最近 24 小时；结束时刻不包含在查询内，与质量事件口径一致。
const form = reactive({
  start: localWatchlistTime(new Date(Date.now() - 86400000)),
  end: localWatchlistTime(new Date(Date.now())),
});
const columns = [
  { title: '命中编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '告警观测时间', key: 'observed', width: 174, className: 'technical' },
  { title: '告警接收时间', key: 'received', width: 174, className: 'technical' },
  { title: '命中字段 / 值', key: 'matches', width: 260 },
  { title: '规则编号', dataIndex: 'rule_id', width: 100, className: 'technical', ellipsis: true },
  { title: '告警规则', key: 'rule', width: 172, ellipsis: true },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '探针编号', dataIndex: 'sensor_id', width: 132, className: 'technical', ellipsis: true },
  { title: '注册代次', dataIndex: 'registration_id', width: 132, className: 'technical', ellipsis: true },
  { title: '命中修订', dataIndex: 'list_revision', width: 90, className: 'technical' },
];
const cappedDays = computed(() => props.page.capped_days.map(day => day.day).join('、'));
const cappedCount = computed(() => formatNumber(watchlistDailyHitCap));
function query() {
  emit('query', form.start, form.end);
}
watch(() => props.listId, query, { immediate: true });
</script>
<template>
  <section aria-label="观察名单命中记录">
    <div class="heading-with-help section-gap">
      <h2>观察名单命中</h2>
      <PageHelp title="观察名单命中"
        ><p>
          新接收的告警按当前修订登记，已有命中按当时修订固化。列表按告警观测时间倒序，记录留存期独立于名单业务有效期。
        </p>
        <p>
          命中供调查复核。攻击成立须结合独立证据，设备动作须另行确认授权。历史数据可通过「历史影响」核对。
        </p></PageHelp
      >
    </div>
    <a-form :model="form" layout="horizontal" @finish="query">
      <ListFilters label="命中记录筛选" :columns="2">
        <TimeRangeField
          v-model:start="form.start"
          v-model:end="form.end"
          id-prefix="watchlist-hit"
          required
          end-hint="结束时刻不包含在查询内，窗口最多 31 天。"
        />
        <template #actions><a-button type="primary" html-type="submit" :loading="pending">查询命中</a-button></template>
      </ListFilters>
    </a-form>
    <a-alert
      v-if="page.capped_days.length"
      type="warning"
      show-icon
      :message="`${cappedDays} 的命中数已达单日上限 ${cappedCount} 条，这些日期有部分命中未逐条登记，列表不完整。`"
      class="section-gap"
    />
    <a-alert
      v-if="error && loaded"
      type="warning"
      show-icon
      message="命中记录更新失败，当前保留上次读取结果"
      :description="error"
      class="section-gap"
    />
    <StatePanel
      :loading="pending && !loaded"
      :error="loaded ? '' : error"
      :empty="loaded && !page.items.length"
      description="当前时间窗内没有命中记录。观察名单只关联修订保存之后接收的新告警；如需核对更早数据，请使用「历史影响」。"
      @retry="emit('retry')"
    >
      <ListTable :columns="columns" :data-source="page.items" :scroll="{ x: 1474 }"
        ><template #bodyCell="{ column, record }">
          <template v-if="column.key === 'observed'">{{ formatTime(record.observed_at) }}</template>
          <template v-else-if="column.key === 'received'">{{ formatTime(record.received_at) }}</template>
          <WatchlistMatchCell v-else-if="column.key === 'matches'" :matches="record.matches" />
          <span v-else-if="column.key === 'rule'" :title="record.rule_name || undefined">{{
            record.rule_name || '规则名称未记录'
          }}</span>
          <StatusTag
            v-else-if="column.key === 'severity'"
            :tone="statusTone(alertSeverityTones, record.severity)"
            :value="watchlistSeverities[record.severity]"
          /> </template
      ></ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="pages"
      :page-size="pageSize"
      :count="pending || error || !loaded ? undefined : page.items.length"
      :has-previous="pages > 1"
      :has-next="!error && !!page.next_cursor"
      :disabled="pending || !loaded"
      @previous="emit('previous')"
      @next="emit('next')"
      @update:page-size="emit('update:pageSize', $event)"
    />
  </section>
</template>
