<script setup lang="ts">
import { computed, reactive, watch } from 'vue';
import { Table as ATable } from 'ant-design-vue';
import StatePanel from './StatePanel.vue';
import {
  localWatchlistTime,
  watchlistDailyHitCap,
  watchlistHitFields,
  watchlistSeverities,
  type WatchlistHitPage,
} from '../watchlists';
import { formatTime } from '../types';
const props = defineProps<{
  listId: string;
  page: WatchlistHitPage;
  pending: boolean;
  error: string;
  loaded: boolean;
  pages: number;
}>();
const emit = defineEmits<{ query: [start: string, end: string]; next: []; previous: []; retry: [] }>();
// 默认窗口为最近 24 小时；结束时刻不包含在查询内，与质量事件口径一致。
const form = reactive({
  start: localWatchlistTime(new Date(Date.now() - 86400000)),
  end: localWatchlistTime(new Date(Date.now())),
});
const columns = [
  { title: '告警观测时间', key: 'observed', width: 190 },
  { title: '命中字段 / 值', key: 'matches', width: 260 },
  { title: '告警规则', key: 'rule', width: 240 },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '探针 / 注册代次', key: 'sensor', width: 190 },
  { title: '命中修订', key: 'revision', width: 90 },
];
const cappedDays = computed(() => props.page.capped_days.map(day => day.day).join('、'));
const cappedCount = computed(() => watchlistDailyHitCap.toLocaleString('en-US'));
function query() {
  emit('query', form.start, form.end);
}
watch(() => props.listId, query, { immediate: true });
</script>
<template>
  <section aria-label="观察名单命中记录">
    <a-alert
      type="info"
      show-icon
      message="命中只关联修订保存后接收的新告警，并绑定当时的修订。命中不表示攻击成立、误报结论或任何设备授权；历史数据请用「历史影响」核对。"
      class="section-gap"
    />
    <a-form :model="form" layout="vertical" class="panel panel-body watchlist-hit-form" @finish="query"
      ><div class="watchlist-hit-fields">
        <a-form-item label="开始时间（本地时间）" html-for="watchlist-hit-start" required
          ><a-input id="watchlist-hit-start" v-model:value="form.start" type="datetime-local" step="1"
        /></a-form-item>
        <a-form-item
          label="结束时间（本地时间）"
          html-for="watchlist-hit-end"
          required
          extra="结束时刻不包含在查询内，窗口最多 31 天。"
          ><a-input id="watchlist-hit-end" v-model:value="form.end" type="datetime-local" step="1"
        /></a-form-item>
      </div>
      <div class="filter-actions">
        <a-button type="primary" html-type="submit" :loading="pending">查询命中</a-button>
      </div></a-form
    >
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
      <div class="table-wrap">
        <a-table
          :columns="columns"
          :data-source="page.items"
          row-key="id"
          :pagination="false"
          :scroll="{ x: 1000 }"
          size="small"
          ><template #bodyCell="{ column, record }">
            <template v-if="column.key === 'observed'"
              >{{ formatTime(record.observed_at)
              }}<small class="page-description watchlist-hit-sub"
                >接收 {{ formatTime(record.received_at) }}</small
              ></template
            >
            <ul v-else-if="column.key === 'matches'" class="watchlist-hit-matches">
              <li v-for="match in record.matches" :key="match.field + '/' + match.value">
                <span class="status status-neutral">{{
                  watchlistHitFields[match.field as keyof typeof watchlistHitFields]
                }}</span><span class="technical watchlist-hit-value">{{ match.value }}</span>
              </li>
            </ul>
            <template v-else-if="column.key === 'rule'"
              ><span v-if="record.rule_name">{{ record.rule_name }}</span
              ><span v-else class="page-description">规则名称未记录</span
              ><small v-if="record.rule_id" class="technical watchlist-hit-sub">{{ record.rule_id }}</small></template
            >
            <span v-else-if="column.key === 'severity'" class="status" :class="'status-' + record.severity">{{
              watchlistSeverities[record.severity as keyof typeof watchlistSeverities]
            }}</span>
            <template v-else-if="column.key === 'sensor'"
              ><span class="technical">{{ record.sensor_id }}</span
              ><small class="technical watchlist-hit-sub">{{ record.registration_id }}</small></template
            >
            <template v-else-if="column.key === 'revision'"
              ><span class="technical">{{ record.list_revision }}</span
              ><small class="page-description watchlist-hit-sub">按当时修订固化</small></template
            >
          </template></a-table
        >
      </div>
    </StatePanel>
    <div class="watchlist-hit-pagination">
      <span class="page-description"
        >按告警观测时间倒序；留存期与名单业务有效期独立，名单停用或修订变化不删除既有命中。</span
      ><a-button :disabled="pending || pages <= 1" @click="emit('previous')">上一页</a-button
      ><span>第 {{ pages }} 页</span
      ><a-button :disabled="pending || !!error || !page.next_cursor" @click="emit('next')">下一页</a-button>
    </div>
  </section>
</template>
<style scoped>
.watchlist-hit-form {
  margin-bottom: var(--section-gap);
  padding-top: var(--panel-inset);
}
.watchlist-hit-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 var(--field-gap);
}
.watchlist-hit-fields .ant-form-item {
  min-width: 0;
}
.watchlist-hit-sub {
  display: block;
  margin-top: var(--label-gap);
  font-size: 12px;
}
.watchlist-hit-matches {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: var(--label-gap);
}
.watchlist-hit-matches > li {
  display: grid;
  gap: var(--label-gap);
  min-width: 0;
}
.watchlist-hit-matches .status {
  justify-self: start;
}
.watchlist-hit-value {
  overflow-wrap: anywhere;
}
.watchlist-hit-pagination {
  display: flex;
  gap: var(--related-gap);
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  padding-top: var(--section-gap);
}
.watchlist-hit-pagination > .page-description {
  flex: 1;
  min-width: 200px;
}
</style>
