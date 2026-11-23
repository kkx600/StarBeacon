<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue';
import { Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import { readWatchlistAlertHits, watchlistHitFields, type WatchlistAlertHits } from '@starbeacon/shared/watchlists.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import { router } from '../../router';
const props = defineProps<{ eventId: string; digest: string }>();
const result = shallowRef<WatchlistAlertHits | null>(null),
  pending = shallowRef(false),
  error = shallowRef('');
let stopped = false,
  read: AbortController | undefined;
function clear() {
  read?.abort();
  read = undefined;
  result.value = null;
  pending.value = false;
  error.value = '';
}
// 读取命中不需要管理员权限；摘要绑定告警身份，摘要不一致不借用其他告警的命中。
async function refresh() {
  if (stopped || !session.current.value) return;
  read?.abort();
  const controller = new AbortController();
  read = controller;
  pending.value = true;
  error.value = '';
  const tenant = session.current.value.tenant_id,
    event = props.eventId,
    sha256 = props.digest,
    timer = setTimeout(() => controller.abort(), 30000);
  try {
    const value = await session.api.request<unknown>(
      `/alerts/${encodeURIComponent(event)}/watchlist-hits?` + new URLSearchParams({ sha256 }),
      { signal: controller.signal },
    );
    if (read !== controller || stopped) return;
    if (controller.signal.aborted) throw new Error('名单命中读取超时，请重试。');
    const checked = await readWatchlistAlertHits(value, tenant, event, sha256);
    if (read !== controller || stopped) return;
    if (controller.signal.aborted) throw new Error('名单命中读取超时，请重试。');
    result.value = checked;
  } catch (cause) {
    if (!stopped && read === controller)
      error.value = controller.signal.aborted
        ? '名单命中读取超时，请重试。'
        : cause instanceof Error
          ? cause.message
          : '名单命中读取失败，请重试。';
  } finally {
    clearTimeout(timer);
    if (read === controller) pending.value = false;
  }
}
// 名单目录是管理员工作区；viewer 可读命中但不能跳转，只显示名单标识。
const canInspect = computed(() => session.current.value?.role === 'admin');
function inspect() {
  if (canInspect.value) void router.push('/detection/watchlists');
}
watch(
  () =>
    [
      session.current.value?.tenant_id,
      session.current.value?.id,
      session.current.value?.role,
      session.current.value?.csrf_token,
    ].join('/'),
  clear,
  { flush: 'sync' },
);
onMounted(() => {
  void refresh();
});
onScopeDispose(() => {
  stopped = true;
  clear();
});
</script>
<template>
  <section aria-label="告警的观察名单命中">
    <a-alert
      type="info"
      show-icon
      message="命中表示该告警与观察名单的关联，不表示攻击成立或已执行封禁。"
      class="section-gap"
    />
    <a-alert
      v-if="error && result"
      type="warning"
      show-icon
      message="名单命中更新失败，当前保留上次读取结果"
      :description="error"
      class="section-gap"
    />
    <StatePanel
      :loading="pending && !result"
      :error="result ? '' : error"
      :empty="!!result && !result.items.length"
      description="该告警未命中任何观察名单。名单只关联修订保存后接收的新告警。"
      @retry="refresh"
    >
      <div v-if="result" class="alert-watchlist-hits">
        <a-descriptions v-for="hit in result.items" :key="hit.id" bordered :column="1" size="small">
          <a-descriptions-item label="名单标识"
            ><button v-if="canInspect" class="link-button technical" @click="inspect">{{ hit.list_id }}</button
            ><span v-else class="technical">{{ hit.list_id }}</span></a-descriptions-item
          >
          <a-descriptions-item label="命中修订">{{ hit.list_revision }}；按当时修订固化。</a-descriptions-item>
          <a-descriptions-item label="命中字段与值"
            ><ul class="alert-watchlist-matches">
              <li v-for="match in hit.matches" :key="match.field + '/' + match.value">
                <span class="status status-neutral">{{ watchlistHitFields[match.field] }}</span><span
                  class="technical"
                  >{{ match.value }}</span
                >
              </li>
            </ul></a-descriptions-item
          >
          <a-descriptions-item label="登记时间">{{ formatTime(hit.created_at) }}</a-descriptions-item>
        </a-descriptions>
      </div>
    </StatePanel>
  </section>
</template>
<style scoped>
.alert-watchlist-hits {
  display: grid;
  gap: var(--section-gap);
}
.alert-watchlist-matches {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  gap: var(--label-gap);
}
.alert-watchlist-matches > li {
  display: flex;
  gap: var(--related-gap);
  align-items: baseline;
  flex-wrap: wrap;
  min-width: 0;
}
.alert-watchlist-matches .technical {
  overflow-wrap: anywhere;
}
</style>
