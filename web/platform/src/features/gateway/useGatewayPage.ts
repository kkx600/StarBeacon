import { onMounted, onScopeDispose, shallowRef } from 'vue';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import type { GatewayPage } from './gatewayBlocks';

export function useGatewayPage<T extends GatewayPage<unknown>>(
  load: (cursor: string, limit: number, signal: AbortSignal) => Promise<T>,
) {
  const data = shallowRef<T>();
  const cursors = shallowRef(['']);
  const loading = shallowRef(true);
  const error = shallowRef('');
  const { pageSize, changePageSize } = useCursorPageSize(cursors, loading, reload);
  let request: AbortController | undefined;

  async function reload() {
    request?.abort();
    const current = new AbortController();
    request = current;
    loading.value = true;
    error.value = '';
    try {
      const result = await load(cursors.value.at(-1) ?? '', pageSize.value, current.signal);
      if (!current.signal.aborted) data.value = result;
    } catch (err) {
      if (!current.signal.aborted) error.value = err instanceof Error ? err.message : '读取失败，请重试。';
    } finally {
      if (request === current) loading.value = false;
    }
  }
  function first() {
    cursors.value = [''];
    void reload();
  }
  function next() {
    const cursor = data.value?.next_cursor;
    if (!cursor || loading.value || error.value) return;
    cursors.value = [...cursors.value, cursor];
    void reload();
  }
  function previous() {
    if (loading.value || cursors.value.length < 2) return;
    cursors.value = cursors.value.slice(0, -1);
    void reload();
  }

  onMounted(reload);
  onScopeDispose(() => request?.abort());
  return { data, cursors, loading, error, pageSize, changePageSize, first, next, previous, reload };
}
