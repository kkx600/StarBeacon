<script setup lang="ts">
import { onMounted, onScopeDispose, reactive, shallowRef, watch } from 'vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import SyslogSourceFilters from '@starbeacon/shared/components/SyslogSourceFilters.vue';
import SyslogSources from '@starbeacon/shared/components/SyslogSources.vue';
import { emptySourceQuery, sourceQuery, readSourcePage, type SyslogSource } from '@starbeacon/shared/syslog.ts';
import { session } from '../session';
const filters = reactive(emptySourceQuery()),
  applied = shallowRef(emptySourceQuery()),
  items = shallowRef<SyslogSource[]>([]),
  pending = shallowRef(false),
  error = shallowRef(''),
  filterError = shallowRef(''),
  cursors = shallowRef(['']),
  nextCursor = shallowRef('');
const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, reloadPage);
let controller: AbortController | undefined,
  stopped = false;
async function refresh() {
  if (stopped) return;
  controller?.abort();
  const current = new AbortController();
  controller = current;
  pending.value = true;
  try {
    const q = { ...applied.value, cursor: cursors.value.at(-1) ?? '', limit: pageSize.value },
      result = readSourcePage(
        await session.api.request(
          '/syslog/sources?' + new URLSearchParams(Object.entries(q).map(([k, v]) => [k, String(v)])),
          { signal: current.signal },
        ),
        q,
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
    applied.value = sourceQuery(filters);
    filterError.value = '';
    cursors.value = [''];
    reloadPage();
  } catch (cause) {
    filterError.value = (cause as Error).message;
  }
}
function reset() {
  Object.assign(filters, emptySourceQuery());
  search();
}
function page(next: boolean) {
  if (pending.value || (next && (!nextCursor.value || error.value)) || (!next && cursors.value.length <= 1)) return;
  cursors.value = next ? [...cursors.value, nextCursor.value] : cursors.value.slice(0, -1);
  reloadPage();
}
function reloadPage() {
  items.value = [];
  nextCursor.value = '';
  void refresh();
}
watch(
  () => [session.current.value?.id, session.current.value?.tenant_id, session.current.value?.role],
  () => {
    controller?.abort();
    items.value = [];
    Object.assign(filters, emptySourceQuery());
    applied.value = emptySourceQuery();
    cursors.value = [''];
    nextCursor.value = '';
    if (session.current.value?.role === 'admin') void refresh();
  },
);
onMounted(() => {
  if (session.current.value?.role === 'admin') void refresh();
});
onScopeDispose(() => {
  stopped = true;
  controller?.abort();
});
</script>
<template>
  <PageHeader
    title="Syslog 接收"
    description="核对采集器的固定日志来源、接收状态与持久缓冲。设备及租户身份以接入绑定为准。"
    notice="TLS 来源校验客户端证书与指纹。TCP、UDP 来源使用授权网段。配置和监听地址由采集器私有文件管理。"
  >
    <a-button :loading="pending" @click="refresh">刷新来源</a-button>
  </PageHeader>
  <SyslogSourceFilters :model="filters" :pending="pending" @search="search" @reset="reset" /><a-alert
    v-if="filterError"
    type="error"
    show-icon
    :message="filterError"
    class="section-gap"
  />
  <section class="panel">
    <div class="panel-header">
      <h2>日志来源</h2>
    </div>
    <div v-if="error && items.length" class="panel-body">
      <a-alert type="warning" show-icon message="来源更新失败，当前显示上次成功读取的目录" :description="error" />
    </div>
    <StatePanel
      :loading="pending && !items.length"
      :error="items.length ? undefined : error"
      :empty="!items.length"
      description="当前条件下没有 Syslog 来源。请调整筛选，或配置采集器来源文件后核对心跳。"
      @retry="refresh"
      ><SyslogSources :items="items"
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
</template>
