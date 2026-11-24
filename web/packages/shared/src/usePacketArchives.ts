import { onScopeDispose, shallowRef, watch } from 'vue';
import type { ApiClient } from './api';
import { defaultPageSize } from './pagination';
import { useCursorPageSize } from './composables/useCursorPageSize';
import { validPacketPage, validPacketRecord, type PacketPage, type PacketRecord } from './packetArchives';

export function usePacketArchives(api: ApiClient, local = false) {
  const page = shallowRef<PacketPage>({ items: [], available: false }),
    pending = shallowRef(true),
    error = shallowRef(''),
    query = shallowRef({ sensor: '', cursor: '', generation: 0 }),
    cursors = shallowRef(['']);
  const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, refresh);
  const selected = shallowRef<PacketRecord | null>(null),
    detailPending = shallowRef(false),
    detailError = shallowRef('');
  let detailController: AbortController | undefined;
  const stop = watch(
    query,
    async (requested, _old, onCleanup) => {
      const controller = new AbortController();
      onCleanup(() => controller.abort());
      pending.value = true;
      error.value = '';
      const limit = pageSize.value;
      const params = new URLSearchParams();
      if (!local && requested.sensor) params.set('sensor_id', requested.sensor);
      if (!local && requested.cursor) params.set('cursor', requested.cursor);
      if (!local && limit !== defaultPageSize) params.set('limit', String(limit));
      try {
        const value = await api.request<unknown>('/packet-archives' + (params.size ? '?' + params.toString() : ''), {
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        if (!validPacketPage(value, local, limit)) throw new Error('原包目录响应不完整，请重新读取');
        page.value = value;
      } catch (e) {
        if (!controller.signal.aborted) error.value = e instanceof Error ? e.message : '原包目录读取失败';
      } finally {
        if (!controller.signal.aborted) pending.value = false;
      }
    },
    { immediate: true },
  );
  function close() {
    detailController?.abort();
    selected.value = null;
    detailPending.value = false;
    detailError.value = '';
  }
  async function view(row: PacketRecord) {
    close();
    selected.value = row;
    detailPending.value = true;
    const controller = new AbortController();
    detailController = controller;
    try {
      const value = await api.request<unknown>('/packet-archives/' + encodeURIComponent(row.id), {
        signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      if (!validPacketRecord(value, local, true) || value.id !== row.id)
        throw new Error('原包详情与所选目录不一致，请重新读取');
      selected.value = value;
    } catch (e) {
      if (!controller.signal.aborted) detailError.value = e instanceof Error ? e.message : '原包详情读取失败';
    } finally {
      if (!controller.signal.aborted) detailPending.value = false;
    }
  }
  function refresh() {
    close();
    cursors.value = [''];
    query.value = { ...query.value, cursor: '', generation: query.value.generation + 1 };
  }
  function filter(sensor: string) {
    close();
    cursors.value = [''];
    query.value = { sensor: sensor.trim(), cursor: '', generation: query.value.generation + 1 };
  }
  function next() {
    if (local || pending.value || error.value || !page.value.next) return;
    close();
    cursors.value = [...cursors.value, page.value.next];
    query.value = { ...query.value, cursor: page.value.next };
  }
  function previous() {
    if (local || pending.value || cursors.value.length <= 1) return;
    close();
    cursors.value = cursors.value.slice(0, -1);
    query.value = { ...query.value, cursor: cursors.value.at(-1) ?? '' };
  }
  onScopeDispose(() => {
    stop();
    close();
  });
  return {
    page,
    pending,
    error,
    selected,
    detailPending,
    detailError,
    cursors,
    pageSize,
    changePageSize,
    view,
    close,
    refresh,
    filter,
    next,
    previous,
  };
}
