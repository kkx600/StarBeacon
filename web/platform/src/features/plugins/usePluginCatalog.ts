import { computed, onScopeDispose, shallowRef, watch } from 'vue';
import { defaultPageSize } from '@starbeacon/shared/pagination.ts';
import type { PluginPage } from '@starbeacon/shared/responsePlugins.ts';
import { session } from '../../session';

export function usePluginCatalog() {
  const page = shallowRef<PluginPage>({ items: [], next_after: '' });
  const cursors = shallowRef(['']);
  const pageSize = shallowRef(defaultPageSize);
  const loading = shallowRef(false);
  const error = shallowRef('');
  const scope = computed(() => {
    const u = session.current.value;
    return u?.role === 'admin' ? u.tenant_id + '/' + u.id : '';
  });
  let controller: AbortController | undefined;
  async function refresh() {
    controller?.abort();
    if (!scope.value) return;
    const current = new AbortController();
    controller = current;
    loading.value = true;
    error.value = '';
    try {
      const query = new URLSearchParams({ limit: String(pageSize.value) });
      const after = cursors.value.at(-1);
      if (after) query.set('after', after);
      const result = await session.api.request<PluginPage>('/response-plugins?' + query, { signal: current.signal });
      if (!current.signal.aborted) page.value = result;
    } catch (cause) {
      if (!current.signal.aborted) error.value = cause instanceof Error ? cause.message : '联动插件读取失败';
    } finally {
      if (controller === current) loading.value = false;
    }
  }
  function move(next: boolean) {
    if (loading.value || (next ? !page.value.next_after : cursors.value.length <= 1)) return;
    cursors.value = next ? [...cursors.value, page.value.next_after] : cursors.value.slice(0, -1);
    page.value = { items: [], next_after: '' };
    void refresh();
  }
  function resize(_page: number, size: number) {
    if (size === pageSize.value) return;
    pageSize.value = size;
    cursors.value = [''];
    void refresh();
  }
  watch(
    scope,
    () => {
      controller?.abort();
      page.value = { items: [], next_after: '' };
      cursors.value = [''];
      loading.value = false;
      void refresh();
    },
    { immediate: true },
  );
  onScopeDispose(() => controller?.abort());
  return { page, cursors, pageSize, loading, error, scope, refresh, move, resize };
}
