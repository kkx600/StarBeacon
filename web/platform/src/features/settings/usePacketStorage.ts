import { onMounted, onScopeDispose, shallowReadonly, shallowRef, watch } from 'vue';
import { validPacketStorage, type PacketStorageSettings } from '@starbeacon/shared/packetRetention.ts';
import { session } from '../../session';

export function usePacketStorage() {
  const settings = shallowRef<PacketStorageSettings | null>(null);
  const pending = shallowRef(false);
  const error = shallowRef('');
  let controller: AbortController | undefined;
  let interval: ReturnType<typeof setInterval> | undefined;

  async function refresh() {
    if (pending.value || session.current.value?.role !== 'admin') return;
    const active = new AbortController();
    controller = active;
    pending.value = true;
    try {
      const value = await session.api.request<unknown>('/packet-storage', { signal: active.signal });
      if (active.signal.aborted) return;
      if (!validPacketStorage(value)) throw new Error('全流量存储响应格式无效，请重试');
      settings.value = value;
      error.value = '';
    } catch (e) {
      if (!active.signal.aborted) error.value = e instanceof Error ? e.message : '无法读取全流量存储';
    } finally {
      if (!active.signal.aborted) pending.value = false;
    }
  }

  watch(
    () => [session.current.value?.id, session.current.value?.tenant_id, session.current.value?.role].join('/'),
    () => {
      controller?.abort();
      settings.value = null;
      pending.value = false;
      error.value = '';
      void refresh();
    },
  );
  onMounted(() => {
    void refresh();
    interval = setInterval(refresh, 15000);
  });
  onScopeDispose(() => {
    controller?.abort();
    clearInterval(interval);
  });
  return {
    settings: shallowReadonly(settings),
    pending: shallowReadonly(pending),
    error: shallowReadonly(error),
    refresh,
  };
}
