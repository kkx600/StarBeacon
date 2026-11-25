import { computed, onScopeDispose, shallowRef, watch, type Ref } from 'vue';
import {
  canSubmitPluginAction,
  isPendingPluginOperation,
  type PluginAction,
  type PluginOperation,
  type PluginOperations,
  type PluginVersion,
} from '@starbeacon/shared/responsePlugins.ts';
import { session } from '../../session';

export function usePluginOperations(plugin: Readonly<Ref<PluginVersion>>, sensor: Readonly<Ref<string>>) {
  const state = shallowRef<PluginOperations | null>(null);
  const loading = shallowRef(false);
  const posting = shallowRef(false);
  const error = shallowRef('');
  const writeError = shallowRef('');
  let read: AbortController | undefined, write: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let attempt: { body: string; key: string } | undefined;
  const endpoint = computed(() => '/response-plugins/' + encodeURIComponent(plugin.value.id) + '/operations');
  const can = (action: PluginAction) =>
    !posting.value &&
    !loading.value &&
    !error.value &&
    canSubmitPluginAction(action, plugin.value.version, state.value);

  async function refresh() {
    read?.abort();
    clearTimeout(timer);
    if (!sensor.value) return;
    const call = new AbortController();
    read = call;
    loading.value = true;
    error.value = '';
    try {
      const query = new URLSearchParams({ sensor_id: sensor.value });
      const result = await session.api.request<PluginOperations>(endpoint.value + '?' + query, { signal: call.signal });
      if (call.signal.aborted) return;
      state.value = result;
      if (result.operations.some(isPendingPluginOperation)) timer = setTimeout(refresh, 2000);
    } catch (cause) {
      if (!call.signal.aborted) error.value = cause instanceof Error ? cause.message : '试运行回执读取失败';
    } finally {
      if (read === call) loading.value = false;
    }
  }
  async function submit(action: PluginAction) {
    const deployment = state.value?.deployment;
    if (!deployment || !can(action)) return;
    const version =
      action === 'rollback'
        ? deployment.previous_version
        : action === 'disable'
          ? deployment.version
          : plugin.value.version;
    const body: PluginOperation = {
      sensor_id: sensor.value,
      action,
      version,
      expected_generation: deployment.generation,
    };
    const fingerprint = JSON.stringify(body);
    if (attempt?.body !== fingerprint) attempt = { body: fingerprint, key: crypto.randomUUID() };
    const call = new AbortController();
    write = call;
    posting.value = true;
    writeError.value = '';
    try {
      await session.api.request<{ task_id: string }>(endpoint.value, {
        method: 'POST',
        body,
        headers: { 'Idempotency-Key': attempt.key },
        signal: call.signal,
      });
      if (!call.signal.aborted) {
        attempt = undefined;
        await refresh();
      }
    } catch (cause) {
      if (!call.signal.aborted) writeError.value = cause instanceof Error ? cause.message : '操作提交失败';
    } finally {
      if (write === call) posting.value = false;
    }
  }

  function cancel() {
    read?.abort();
    write?.abort();
    clearTimeout(timer);
  }
  watch(
    [endpoint, sensor],
    () => {
      cancel();
      attempt = undefined;
      state.value = null;
      loading.value = posting.value = false;
      error.value = writeError.value = '';
      void refresh();
    },
    { immediate: true },
  );
  onScopeDispose(cancel);
  return { state, loading, posting, error, writeError, can, refresh, submit };
}
