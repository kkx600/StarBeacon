<script setup lang="ts">
import { onMounted, onScopeDispose, reactive, shallowRef, watch } from 'vue';
import { Select as ASelect, SelectOption as ASelectOption } from 'ant-design-vue';
import type { ApiClient } from '../api';
import type { Principal } from '../types';
import { emptyLogQuery, logQuery, readLogDetail, readLogPage, type LogDocument, type LogQuery } from '../syslog';
import StatePanel from './StatePanel.vue';
import PageHeader from './PageHeader.vue';
import ListFilters from './ListFilters.vue';
import ListPager from './ListPager.vue';
import TimeRangeField from './TimeRangeField.vue';
import { useCursorPageSize } from '../composables/useCursorPageSize';
import SyslogLogTable from './SyslogLogTable.vue';
import SyslogLogDetail from './SyslogLogDetail.vue';
const props = defineProps<{
    api?: ApiClient;
    principal?: Principal | null;
    preview?: readonly LogDocument[];
    state?: string;
  }>(),
  emit = defineEmits<{ state: [state: string] }>();
const filters = reactive(emptyLogQuery()),
  applied = shallowRef<LogQuery>({ ...filters }),
  items = shallowRef<LogDocument[]>([]),
  pending = shallowRef(false),
  error = shallowRef(''),
  filterError = shallowRef(''),
  nextCursor = shallowRef(''),
  cursors = shallowRef(['']),
  detail = shallowRef<LogDocument | null>(null),
  detailOpen = shallowRef(false),
  detailPending = shallowRef(false),
  detailError = shallowRef(''),
  target = shallowRef<LogDocument | null>(null);
const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, reloadPage);
let controller: AbortController | undefined,
  detailController: AbortController | undefined,
  stopped = false;
function localTime(value: string) {
  const d = new Date(value);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}
const window = reactive({ start: localTime(filters.start), end: localTime(filters.end) });
async function refresh() {
  if (stopped) return;
  if (!props.api) {
    items.value = [...(props.preview ?? [])];
    emit('state', 'data');
    return;
  }
  controller?.abort();
  const current = new AbortController();
  controller = current;
  pending.value = true;
  try {
    const q = { ...applied.value, cursor: cursors.value.at(-1) ?? '', limit: pageSize.value },
      result = readLogPage(
        await props.api.request('/logs/search', { method: 'POST', body: q, signal: current.signal }),
        q,
        props.principal?.tenant_id ?? '',
      );
    if (current.signal.aborted) return;
    items.value = result.items;
    nextCursor.value = result.next_cursor;
    error.value = '';
  } catch (cause) {
    if (!current.signal.aborted) error.value = (cause as Error).message;
  } finally {
    if (controller === current) pending.value = false;
  }
}
function search() {
  try {
    applied.value = logQuery({
      ...filters,
      start: new Date(window.start).toISOString(),
      end: new Date(window.end).toISOString(),
      cursor: '',
    });
    filterError.value = '';
    cursors.value = [''];
    reloadPage();
  } catch (cause) {
    filterError.value = cause instanceof RangeError ? '请选择有效的开始与结束时间。' : (cause as Error).message;
  }
}
function reset() {
  Object.assign(filters, emptyLogQuery());
  window.start = localTime(filters.start);
  window.end = localTime(filters.end);
  search();
}
function page(next: boolean) {
  if (pending.value || (next && (!nextCursor.value || error.value)) || (!next && cursors.value.length <= 1)) return;
  cursors.value = next ? [...cursors.value, nextCursor.value] : cursors.value.slice(0, -1);
  reloadPage();
}
function reloadPage() {
  close();
  items.value = [];
  nextCursor.value = '';
  void refresh();
}
async function view(row: LogDocument) {
  detailController?.abort();
  target.value = row;
  detailOpen.value = true;
  detail.value = null;
  detailError.value = '';
  if (!props.api) {
    detail.value = props.preview?.find(v => v.event_id === row.event_id) ?? null;
    return;
  }
  const current = new AbortController();
  detailController = current;
  detailPending.value = true;
  try {
    const data = await readLogDetail(
      await props.api.request(`/logs/${row.event_id}?partition=${encodeURIComponent(row.partition)}`, {
        signal: current.signal,
      }),
      props.principal?.tenant_id ?? '',
      row.event_id,
      row.partition,
    );
    if (current.signal.aborted) return;
    detail.value = data;
  } catch (cause) {
    if (!current.signal.aborted) detailError.value = (cause as Error).message;
  } finally {
    if (detailController === current) detailPending.value = false;
  }
}
function close() {
  detailController?.abort();
  detailOpen.value = false;
  detailPending.value = false;
  detail.value = null;
  target.value = null;
  if (props.state === 'detail') emit('state', 'data');
}
watch(
  () => [props.state, props.preview],
  () => {
    if (props.api) return;
    if (props.preview?.[0]) {
      const at = Date.parse(props.preview[0].received_at);
      filters.start = new Date(at - 3600000).toISOString();
      filters.end = new Date(at + 3600000).toISOString();
      window.start = localTime(filters.start);
      window.end = localTime(filters.end);
    }
    pending.value = props.state === 'loading';
    error.value = props.state === 'error' ? '日志检索暂时不可用，请重试。' : '';
    items.value = ['empty', 'error', 'loading'].includes(props.state ?? '') ? [] : [...(props.preview ?? [])];
    if (props.state === 'detail' && items.value[0]) void view(items.value[0]);
    else close();
  },
  { immediate: true },
);
watch(
  () => [props.principal?.id, props.principal?.tenant_id, props.principal?.role],
  () => {
    controller?.abort();
    close();
    items.value = [];
    nextCursor.value = '';
    cursors.value = [''];
    Object.assign(filters, emptyLogQuery());
    applied.value = { ...filters };
    window.start = localTime(filters.start);
    window.end = localTime(filters.end);
    if (props.api && props.principal?.role === 'admin') void refresh();
  },
);
onMounted(() => {
  if (props.api && props.principal?.role === 'admin') void refresh();
});
onScopeDispose(() => {
  stopped = true;
  controller?.abort();
  detailController?.abort();
});
</script>
<template>
  <PageHeader
    title="日志检索"
    description="检索 Syslog 消息与解析字段。按平台接收时间筛选，原文查看单独登记审计。"
    notice="检索时间按浏览器本地时区输入。按接收时间和事件标识续页，重新查询可核对最新记录。"
  >
    <a-button :loading="pending" @click="refresh">刷新结果</a-button>
  </PageHeader>
  <a-form :model="window" layout="horizontal" @finish="search">
    <ListFilters label="日志检索条件" :columns="4">
      <TimeRangeField
        id-prefix="syslog-received"
        v-model:start="window.start"
        v-model:end="window.end"
        start-label="接收开始"
        end-label="接收结束"
        required
      />
      <label
        ><span>接入探针</span
        ><a-input v-model:value="filters.sensor_id" aria-label="日志探针" :maxlength="64" allow-clear /></label
      ><label
        ><span>来源标识</span
        ><a-input v-model:value="filters.source_id" aria-label="日志来源" :maxlength="64" allow-clear /></label
      ><label
        ><span>网络域</span
        ><a-input v-model:value="filters.network_domain" aria-label="日志网络域" :maxlength="64" allow-clear /></label
      ><label
        ><span>传输对端 IP</span
        ><a-input v-model:value="filters.peer_ip" aria-label="日志传输对端 IP" :maxlength="45" allow-clear /></label
      ><label
        ><span>原文声明主机</span
        ><a-input v-model:value="filters.hostname" aria-label="日志声明主机" :maxlength="256" allow-clear /></label
      ><label
        ><span>应用名</span
        ><a-input v-model:value="filters.application" aria-label="日志应用" :maxlength="256" allow-clear /></label
      ><label
        ><span>解析状态</span
        ><a-select v-model:value="filters.state" aria-label="日志解析状态"
          ><a-select-option value="">全部状态</a-select-option><a-select-option value="parsed">解析成功</a-select-option
          ><a-select-option value="quarantined">解析隔离</a-select-option></a-select
        ></label
      ><label
        ><span>Syslog 严重级别</span
        ><a-select
          :value="filters.severity ?? ''"
          @change="(value: unknown) => (filters.severity = typeof value === 'number' ? value : null)"
          aria-label="Syslog 严重级别"
          ><a-select-option value="">全部级别</a-select-option
          ><a-select-option
            v-for="(label, i) in ['紧急', '警戒', '严重', '错误', '警告', '通知', '信息', '调试']"
            :key="i"
            :value="i"
            >{{ i }} · {{ label }}</a-select-option
          ></a-select
        ></label
      ><label
        ><span>正文关键词</span
        ><a-input v-model:value="filters.keyword" aria-label="日志正文关键词" :maxlength="256" allow-clear
      /></label>
      <template #actions>
        <a-button type="primary" html-type="submit" :disabled="pending">查询</a-button
        ><a-button :disabled="pending" @click="reset">重置</a-button>
      </template>
    </ListFilters>
  </a-form>
  <a-alert v-if="filterError" show-icon type="error" :message="filterError" class="section-gap" />
  <section class="panel">
    <div class="panel-header">
      <h2>日志记录</h2>
    </div>
    <div v-if="error && items.length" class="panel-body">
      <a-alert type="warning" show-icon message="日志更新失败，当前保留上次结果" :description="error" />
    </div>
    <StatePanel
      :loading="pending && !items.length"
      :error="items.length ? undefined : error"
      :empty="!items.length"
      description="当前条件下没有日志记录。请调整接收时间、来源或关键词，并核对采集器接收与平台索引状态。"
      @retry="refresh"
      ><SyslogLogTable :items="items" @view="view"
    /></StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="error && !items.length ? undefined : items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!nextCursor"
      :disabled="pending"
      @previous="page(false)"
      @next="page(true)"
      @update:page-size="changePageSize"
    />
  </section>
  <SyslogLogDetail
    :open="detailOpen"
    :document="detail"
    :pending="detailPending"
    :error="detailError"
    @close="close"
    @retry="target && view(target)"
  />
</template>
