import { onMounted, onScopeDispose, shallowReadonly, shallowRef } from 'vue';
import { ApiError } from '@starbeacon/shared/api.ts';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import { defaultPageSize } from '@starbeacon/shared/pagination.ts';
import { session } from '../../session';
import {
  validPlan,
  validPlanPage,
  validRunPage,
  type ReportPlan,
  type ReportPlanChange,
  type ReportPlanRun,
  type ReportPlanPage,
  type ReportRunPage,
} from './plans';

export function useReportPlans() {
  const items = shallowRef<ReportPlan[]>([]),
    available = shallowRef(false),
    modelsAvailable = shallowRef(false),
    pending = shallowRef(true),
    error = shallowRef(''),
    busy = shallowRef(false),
    actionError = shallowRef(''),
    unconfirmed = shallowRef(false);
  const runs = shallowRef<ReportPlanRun[]>([]),
    next = shallowRef(''),
    cursors = shallowRef(['']),
    runsPending = shallowRef(false),
    runsError = shallowRef('');
  const { pageSize, changePageSize } = useCursorPageSize(cursors, runsPending, loadRuns);
  let stopped = false,
    listEpoch = 0,
    runsEpoch = 0,
    listControl: AbortController | undefined,
    runsControl: AbortController | undefined,
    mutation: AbortController | undefined,
    selectedID = '';
  let attempt: ReportPlanChange | undefined;
  async function refresh() {
    if (stopped) return;
    const epoch = ++listEpoch;
    listControl?.abort();
    const controller = new AbortController();
    listControl = controller;
    pending.value = true;
    error.value = '';
    try {
      const page = await session.api.request<ReportPlanPage>('/analysis/plans', { signal: controller.signal });
      if (stopped || epoch !== listEpoch) return;
      if (!validPlanPage(page)) throw new Error('报告计划未能完整返回');
      items.value = page.items;
      available.value = page.execution_available;
      modelsAvailable.value = page.model_execution_available;
    } catch (e) {
      if (!controller.signal.aborted) error.value = e instanceof Error ? e.message : '报告计划读取失败';
    } finally {
      if (!stopped && epoch === listEpoch) pending.value = false;
    }
  }
  async function loadRuns(id = selectedID) {
    if (stopped || !id) return;
    if (id !== selectedID) {
      runs.value = [];
      next.value = '';
      cursors.value = [''];
      pageSize.value = defaultPageSize;
    }
    selectedID = id;
    const epoch = ++runsEpoch;
    runsControl?.abort();
    const controller = new AbortController();
    runsControl = controller;
    runsPending.value = true;
    runsError.value = '';
    const before = cursors.value.at(-1) ?? '',
      limit = pageSize.value;
    try {
      const query = new URLSearchParams();
      if (before) query.set('before', before);
      if (limit !== defaultPageSize) query.set('limit', String(limit));
      const page = await session.api.request<ReportRunPage>(
        '/analysis/plans/' + encodeURIComponent(id) + '/runs' + (query.size ? '?' + query : ''),
        { signal: controller.signal },
      );
      if (stopped || epoch !== runsEpoch) return;
      if (!validRunPage(page, limit)) throw new Error('计划运行记录未能完整返回');
      runs.value = page.items;
      next.value = page.next_cursor;
    } catch (e) {
      if (!controller.signal.aborted) runsError.value = e instanceof Error ? e.message : '计划运行记录读取失败';
    } finally {
      if (!stopped && epoch === runsEpoch) runsPending.value = false;
    }
  }
  function previousPage() {
    if (runsPending.value || cursors.value.length <= 1) return;
    cursors.value = cursors.value.slice(0, -1);
    void loadRuns();
  }
  function nextPage() {
    if (runsPending.value || runsError.value || !next.value) return;
    cursors.value = [...cursors.value, next.value];
    void loadRuns();
  }
  function closeRuns() {
    runsEpoch++;
    runsControl?.abort();
    selectedID = '';
    runs.value = [];
    next.value = '';
    cursors.value = [''];
    pageSize.value = defaultPageSize;
    runsError.value = '';
    runsPending.value = false;
  }
  async function save(change: ReportPlanChange) {
    if (stopped || busy.value) return undefined;
    if (attempt && JSON.stringify(attempt) !== JSON.stringify(change)) {
      actionError.value = '上次保存结果尚未确认，请先确认原请求。';
      return undefined;
    }
    if (!attempt) attempt = structuredClone(change);
    const controller = new AbortController();
    mutation = controller;
    busy.value = true;
    actionError.value = '';
    try {
      const plan = await session.api.request<ReportPlan>('/analysis/plans', {
        method: 'POST',
        body: attempt,
        signal: controller.signal,
      });
      if (stopped || controller.signal.aborted) return undefined;
      if (
        !validPlan(plan) ||
        plan.id !== attempt.id ||
        plan.revision !== attempt.expected_revision + 1 ||
        Object.keys(attempt.spec).some(
          key => plan.spec[key as keyof ReportPlan['spec']] !== attempt!.spec[key as keyof ReportPlan['spec']],
        )
      )
        throw new Error('保存结果未能完整返回，请确认原请求');
      attempt = undefined;
      unconfirmed.value = false;
      void refresh();
      return plan;
    } catch (e) {
      if (!controller.signal.aborted) {
        actionError.value = e instanceof Error ? e.message : '报告计划保存结果未确认';
        if (e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 408) {
          attempt = undefined;
          unconfirmed.value = false;
        } else unconfirmed.value = true;
      }
      return undefined;
    } finally {
      if (mutation === controller) {
        mutation = undefined;
        busy.value = false;
      }
    }
  }
  async function confirm() {
    if (attempt) return save(attempt);
    return undefined;
  }
  function clearAction() {
    if (!unconfirmed.value) actionError.value = '';
  }
  onMounted(() => {
    void refresh();
  });
  onScopeDispose(() => {
    stopped = true;
    listEpoch++;
    runsEpoch++;
    listControl?.abort();
    runsControl?.abort();
    mutation?.abort();
  });
  return {
    items: shallowReadonly(items),
    available: shallowReadonly(available),
    modelsAvailable: shallowReadonly(modelsAvailable),
    pending: shallowReadonly(pending),
    error: shallowReadonly(error),
    busy: shallowReadonly(busy),
    actionError: shallowReadonly(actionError),
    unconfirmed: shallowReadonly(unconfirmed),
    runs: shallowReadonly(runs),
    next: shallowReadonly(next),
    cursors: shallowReadonly(cursors),
    pageSize: shallowReadonly(pageSize),
    runsPending: shallowReadonly(runsPending),
    runsError: shallowReadonly(runsError),
    refresh,
    loadRuns,
    previousPage,
    nextPage,
    changePageSize,
    closeRuns,
    save,
    confirm,
    clearAction,
  };
}
