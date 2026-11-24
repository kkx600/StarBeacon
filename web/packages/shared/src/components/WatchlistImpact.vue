<script setup lang="ts">
import { formatNumber } from '../utils/format';
import { computed, reactive, watch } from 'vue';
import { InputNumber as AInputNumber } from 'ant-design-vue';
import StatePanel from './StatePanel.vue';
import MetricBar from './MetricBar.vue';
import ListTable from './ListTable.vue';
import ListFilters from './ListFilters.vue';
import TimeRangeField from './TimeRangeField.vue';
import PageHelp from './PageHelp.vue';
import StatusTag from './StatusTag.vue';
import WatchlistMatchCell from './WatchlistMatchCell.vue';
import { tablePagination } from '../pagination';
import { alertSeverityTones, statusTone } from '../statusTones';
import {
  localWatchlistTime,
  watchlistHitFields,
  watchlistKinds,
  watchlistSeverities,
  type WatchlistImpact,
} from '../watchlists';
import { formatTime } from '../types';
const props = defineProps<{
  listId: string;
  revision: number;
  maximum: number;
  result: WatchlistImpact | null;
  pending: boolean;
  error: string;
  incomplete: boolean;
}>();
const emit = defineEmits<{ run: [revision: number, start: string, end: string]; change: [] }>();
const form = reactive({
  revision: props.revision as number | null,
  start: localWatchlistTime(new Date(Date.now() - 86400000)),
  end: localWatchlistTime(new Date(Date.now())),
});
const validRevision = computed(
  () =>
    form.revision !== null &&
    Number.isSafeInteger(form.revision) &&
    form.revision >= 1 &&
    form.revision <= props.maximum,
);
const valueColumns = [
  { title: '匹配值', key: 'value', width: 320 },
  { title: '命中数', key: 'count', width: 120 },
];
const sampleColumns = [
  { title: '告警编号', dataIndex: 'event_id', width: 142, ellipsis: true, className: 'technical' },
  { title: '告警观测时间', key: 'observed', width: 190 },
  { title: '命中字段 / 值', key: 'matches', width: 260 },
  { title: '告警规则', key: 'rule', width: 240 },
  { title: '严重级别', key: 'severity', width: 100 },
  { title: '探针编号', dataIndex: 'sensor_id', width: 130, ellipsis: true, className: 'technical' },
  { title: '注册代次', dataIndex: 'registration_id', width: 130, ellipsis: true, className: 'technical' },
];
const fieldLabels = computed(() =>
  (props.result?.fields ?? []).map(field => watchlistHitFields[field as keyof typeof watchlistHitFields] ?? field),
);
const metrics = computed(() =>
  props.result
    ? [{ label: '命中告警总数', value: formatNumber(props.result.total), note: '当次核对的已索引告警条数' }]
    : [],
);
function run() {
  if (!props.pending && validRevision.value && form.revision !== null) emit('run', form.revision, form.start, form.end);
}
function choose(v: number | string | null) {
  form.revision = v === null || v === '' ? null : Number(v);
}
watch(
  () => [props.listId, props.revision].join('/'),
  () => {
    form.revision = props.revision;
    emit('change');
  },
);
watch(
  () => [form.revision, form.start, form.end].join('/'),
  () => emit('change'),
);
</script>
<template>
  <section aria-label="观察名单历史影响预览">
    <div class="heading-with-help section-gap">
      <h2>历史影响预览</h2>
      <PageHelp title="历史影响预览"
        ><p>只核对已入索引的告警和已支持的检索字段。历史核对与命中登记、设备动作分别管理。</p>
        <p>TLS SNI 与 DNS 查询名暂无可供预览的检索字段。</p></PageHelp
      >
    </div>
    <a-form :model="form" layout="horizontal" @finish="run">
      <ListFilters label="历史影响筛选" :columns="2">
        <TimeRangeField
          v-model:start="form.start"
          v-model:end="form.end"
          id-prefix="watchlist-impact"
          required
          end-hint="结束时刻不包含在查询内，窗口最多 31 天。"
        />
        <a-form-item label="修订号" html-for="watchlist-impact-revision" required extra="按所选修订当时的定义核对。"
          ><a-input-number
            id="watchlist-impact-revision"
            :value="form.revision ?? ''"
            @update:value="choose"
            :min="1"
            :max="maximum"
            :precision="0"
            :disabled="pending"
        /></a-form-item>
        <template #actions>
          <a-button type="primary" html-type="submit" :loading="pending" :disabled="pending || !validRevision"
            >执行预览</a-button
          >
        </template>
      </ListFilters>
    </a-form>
    <a-alert
      v-if="incomplete"
      type="error"
      show-icon
      message="历史检索结果不完整，本次未交付计数"
      description="本次核对未取得精确计数，已不显示任何部分数字。请稍后重试或缩小核对窗口。"
      class="section-gap"
    />
    <StatePanel :loading="pending" :error="incomplete ? '' : error" @retry="run">
      <template v-if="result && !incomplete">
        <!-- 预览不限定名单类型；保护名单只做只读核对，实时命中只对启用的观察名单登记。 -->
        <p class="page-description section-gap">
          {{ watchlistKinds[result.kind] }} · 修订 {{ result.list_revision
          }}{{ result.current ? '（当前修订）' : '（历史修订）'
          }}<template v-if="result.kind === 'protect'">；保护名单不会自动登记命中，本次结果仅用于核对。</template>
        </p>
        <div class="panel watchlist-impact-summary">
          <MetricBar :items="metrics" embedded />
          <div class="watchlist-impact-context">
            <span>核对时间</span>
            <strong class="technical watchlist-impact-time">{{ formatTime(result.checked_at) }}</strong>
            <small>快照时刻，不随后续告警更新</small>
          </div>
          <div class="watchlist-impact-context">
            <span>参与字段</span>
            <span class="watchlist-impact-tags"
              ><StatusTag v-for="label in fieldLabels" :key="label" tone="neutral" :value="label"
            /></span>
            <small>实际查询的已索引字段</small>
          </div>
        </div>
        <h3 class="watchlist-impact-title">每值命中数</h3>
        <ListTable :columns="valueColumns" :data-source="result.values" row-key="value" :pagination="tablePagination()"
          ><template #bodyCell="{ column, record }">
            <span v-if="column.key === 'value'" class="technical watchlist-impact-value">{{ record.value }}</span>
            <span v-else-if="column.key === 'count'" class="technical watchlist-impact-count">{{
              formatNumber(record.count)
            }}</span>
          </template></ListTable
        >
        <h3 class="watchlist-impact-title">告警样本</h3>
        <p v-if="!result.samples.length" class="page-description">当次核对没有可展示的样本。</p>
        <ListTable
          v-else
          :columns="sampleColumns"
          :data-source="result.samples"
          row-key="event_id"
          :pagination="tablePagination()"
          :scroll="{ x: 1192 }"
          ><template #bodyCell="{ column, record }">
            <template v-if="column.key === 'observed'">{{ formatTime(record['@timestamp']) }}</template>
            <WatchlistMatchCell v-else-if="column.key === 'matches'" :matches="record.matches" />
            <template v-else-if="column.key === 'rule'"
              ><span v-if="record.rule_name">{{ record.rule_name }}</span
              ><span v-else class="page-description">规则名称未记录</span></template
            >
            <StatusTag
              v-else-if="column.key === 'severity'"
              :tone="statusTone(alertSeverityTones, record.severity)"
              :value="watchlistSeverities[record.severity]"
            /> </template
        ></ListTable>
        <p class="page-description watchlist-impact-footnote">
          预览结果为当次核对的快照，不随后续告警更新；本次未登记任何命中，也未授予执行许可。
        </p>
      </template>
      <p v-else-if="!incomplete" class="page-description">点击“执行预览”核对所选修订在该窗口内的已索引告警。</p>
    </StatePanel>
  </section>
</template>
<style scoped>
.watchlist-impact-summary {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
}
.watchlist-impact-context {
  display: flex;
  flex-direction: column;
  gap: var(--label-gap);
  min-width: 0;
  padding: var(--related-gap) var(--panel-inset);
  border-inline-start: 1px solid var(--line);
  color: var(--muted);
  font-size: 12px;
}
.watchlist-impact-context small {
  font-size: 12px;
}
.watchlist-impact-time {
  font-size: 16px;
  font-weight: 600;
  overflow-wrap: anywhere;
}
.watchlist-impact-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--label-gap);
  margin: var(--label-gap) 0;
}
.watchlist-impact-title {
  font-size: 14px;
  margin: var(--section-gap) 0 var(--related-gap);
}
.watchlist-impact-value {
  overflow-wrap: anywhere;
}
.watchlist-impact-count {
  display: block;
  text-align: right;
}
.watchlist-impact-footnote {
  margin-top: var(--section-gap);
}
</style>
