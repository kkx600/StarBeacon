import { computed, onScopeDispose, shallowRef } from 'vue';
import { ApiError } from '@starbeacon/shared/api.ts';
import { defaultPageSize } from '@starbeacon/shared/pagination.ts';
import type { PluginDraft } from '@starbeacon/shared/responsePlugins.ts';
import type { ModelProvider, ModelResult } from '../models/models';
import { session } from '../../session';

const endpoint = '/response-plugin-generation/jobs';
export const deviceTypes = { firewall: '防火墙', waf: 'WAF', edr: 'EDR', other: '其他设备' } as const;
export const generationAbilities = {
  health: '健康检查',
  pull_alerts: '拉取告警',
  block: '封禁、核验与解封',
  isolate: '终端隔离、核验与解除',
} as const;

export type DeviceType = keyof typeof deviceTypes;
export type Ability = keyof typeof generationAbilities;
export type GeneratedPlugin = Omit<PluginDraft, 'id' | 'expected_version'>;
export interface GenerationRequest {
  provider_id: string;
  provider_revision: number;
  device_type: DeviceType;
  abilities: Ability[];
  documentation: string;
  allow_context: boolean;
}
export interface GenerationJob {
  id: string;
  provider_id: string;
  provider_revision: number;
  device_type: DeviceType;
  abilities: Ability[];
  model: string;
  documentation_sha256: string;
  prompt_version: string;
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'refused' | 'incomplete' | 'uncertain' | 'cancelled';
  result: ModelResult;
  candidate?: GeneratedPlugin;
  created_at: string;
  finished_at: string | null;
}
interface GenerationPage {
  items: GenerationJob[];
  next_cursor: string;
  model_execution_available: boolean;
}
const initialPage: GenerationPage = { items: [], next_cursor: '', model_execution_available: false };
const errorMessage = (err: unknown, fallback: string) => (err instanceof Error ? err.message : fallback);

export function usePluginGeneration() {
  const providers = shallowRef<ModelProvider[]>([]);
  const page = shallowRef(initialPage);
  const cursors = shallowRef(['']);
  const pageSize = shallowRef(defaultPageSize);
  const selected = shallowRef<GenerationJob | null>(null);
  const optionsError = shallowRef('');
  const historyError = shallowRef('');
  const detailError = shallowRef('');
  const submitError = shallowRef('');
  const optionsLoading = shallowRef(false);
  const historyLoading = shallowRef(false);
  const detailLoading = shallowRef(false);
  const posting = shallowRef(false);
  const unresolved = shallowRef(false);
  let optionsCall: AbortController | undefined;
  let historyCall: AbortController | undefined;
  let detailCall: AbortController | undefined;
  let writeCall: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let attempt: { input: GenerationRequest; key: string } | undefined;
  const available = computed(() => page.value.model_execution_available && providers.value.length > 0);

  async function loadProviders() {
    optionsCall?.abort();
    const call = new AbortController();
    optionsCall = call;
    optionsLoading.value = true;
    optionsError.value = '';
    try {
      const result = await session.api.request<{ items: ModelProvider[]; available: boolean }>('/models/providers', {
        signal: call.signal,
      });
      if (!call.signal.aborted) providers.value = result.available ? result.items.filter(p => p.enabled) : [];
    } catch (err) {
      if (!call.signal.aborted) optionsError.value = errorMessage(err, '模型选项读取失败');
    } finally {
      if (optionsCall === call) optionsLoading.value = false;
    }
  }

  async function loadHistory() {
    historyCall?.abort();
    const call = new AbortController();
    historyCall = call;
    historyLoading.value = true;
    historyError.value = '';
    try {
      const query = new URLSearchParams();
      const before = cursors.value.at(-1);
      if (before) query.set('before', before);
      if (pageSize.value !== defaultPageSize) query.set('limit', String(pageSize.value));
      const result = await session.api.request<GenerationPage>(query.size ? endpoint + '?' + query : endpoint, {
        signal: call.signal,
      });
      if (!call.signal.aborted) page.value = result;
    } catch (err) {
      if (!call.signal.aborted) historyError.value = errorMessage(err, '生成记录读取失败');
    } finally {
      if (historyCall === call) historyLoading.value = false;
    }
  }

  function move(next: boolean) {
    if (historyLoading.value || (next ? !page.value.next_cursor : cursors.value.length < 2)) return;
    cursors.value = next ? [...cursors.value, page.value.next_cursor] : cursors.value.slice(0, -1);
    void loadHistory();
  }

  function resize(_page: number, size: number) {
    if (size === pageSize.value) return;
    pageSize.value = size;
    cursors.value = [''];
    void loadHistory();
  }

  async function inspect(id: string) {
    detailCall?.abort();
    clearTimeout(timer);
    const call = new AbortController();
    detailCall = call;
    detailLoading.value = true;
    detailError.value = '';
    if (selected.value?.id !== id) selected.value = null;
    try {
      const job = await session.api.request<GenerationJob>(endpoint + '/' + encodeURIComponent(id), {
        signal: call.signal,
      });
      if (!call.signal.aborted) {
        selected.value = job;
        if (job.state === 'queued' || job.state === 'running') timer = setTimeout(() => inspect(id), 2000);
      }
    } catch (err) {
      if (!call.signal.aborted) detailError.value = errorMessage(err, '生成结果读取失败');
    } finally {
      if (detailCall === call) detailLoading.value = false;
    }
  }

  async function submit(input?: GenerationRequest) {
    if (posting.value || (input && unresolved.value)) return false;
    if (input) attempt = { input, key: crypto.randomUUID() };
    if (!attempt) return false;
    const call = new AbortController();
    writeCall = call;
    posting.value = true;
    submitError.value = '';
    try {
      const job = await session.api.request<GenerationJob>(endpoint, {
        method: 'POST',
        body: attempt.input,
        headers: { 'Idempotency-Key': attempt.key },
        signal: call.signal,
      });
      if (call.signal.aborted) return false;
      attempt = undefined;
      unresolved.value = false;
      cursors.value = [''];
      selected.value = job;
      void loadHistory();
      void inspect(job.id);
      return true;
    } catch (err) {
      if (!call.signal.aborted) {
        unresolved.value = !(err instanceof ApiError && err.status >= 400 && err.status < 500);
        if (!unresolved.value) attempt = undefined;
        submitError.value = errorMessage(err, '生成提交结果暂时无法核对');
      }
      return false;
    } finally {
      if (writeCall === call) posting.value = false;
    }
  }

  onScopeDispose(() => {
    optionsCall?.abort();
    historyCall?.abort();
    detailCall?.abort();
    writeCall?.abort();
    clearTimeout(timer);
  });
  return {
    providers,
    page,
    cursors,
    pageSize,
    selected,
    available,
    optionsError,
    historyError,
    detailError,
    submitError,
    optionsLoading,
    historyLoading,
    detailLoading,
    posting,
    unresolved,
    loadProviders,
    loadHistory,
    move,
    resize,
    inspect,
    submit,
  };
}
