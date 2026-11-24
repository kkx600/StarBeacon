import { onScopeDispose, shallowReadonly, shallowRef, watch } from 'vue';
import { ApiError } from '@starbeacon/shared/api.ts';
import { defaultPageSize } from '@starbeacon/shared/pagination.ts';
import {
  readWatchlistHitPage,
  watchlistHitPath,
  watchlistHitQuery,
  type WatchlistHitPage,
  type WatchlistHitQuery,
} from '@starbeacon/shared/watchlists.ts';
import { session } from '../../session';

const empty = (): WatchlistHitPage => ({ items: [], next_cursor: '', observed_at: '', capped_days: [] });

// 命中按告警观测时间倒序游标翻页；游标绑定租户、名单与窗口，失效时从窗口终点重读而不是提示服务不可用。
export function useWatchlistHits() {
  const page = shallowRef<WatchlistHitPage>(empty()),
    pending = shallowRef(false),
    error = shallowRef(''),
    loaded = shallowRef(false);
  const query = shallowRef<WatchlistHitQuery | null>(null),
    cursors = shallowRef<string[]>(['']);
  let stopped = false,
    read: AbortController | undefined;
  function clear() {
    read?.abort();
    read = undefined;
    page.value = empty();
    pending.value = false;
    error.value = '';
    loaded.value = false;
    query.value = null;
    cursors.value = [''];
  }
  async function refresh(retried = false): Promise<void> {
    const scope = query.value;
    if (stopped || !session.current.value || !scope) return;
    read?.abort();
    const controller = new AbortController();
    read = controller;
    pending.value = true;
    error.value = '';
    const tenant = session.current.value.tenant_id,
      cursor = cursors.value.at(-1) ?? '',
      request = { ...scope, cursor },
      timer = setTimeout(() => controller.abort(), 30000);
    try {
      const value = await session.api.request<unknown>(watchlistHitPath(request), { signal: controller.signal });
      if (read !== controller || stopped) return;
      if (controller.signal.aborted) throw new Error('命中记录读取超时，请重试。');
      const checked = await readWatchlistHitPage(value, request, tenant);
      if (read !== controller || stopped) return;
      if (controller.signal.aborted) throw new Error('命中记录读取超时，请重试。');
      page.value = checked;
      loaded.value = true;
    } catch (cause) {
      if (stopped || read !== controller) return;
      // 游标非法由平台返回 400；清空游标并从窗口终点重读一次，不按服务不可用提示用户。
      if (!retried && cursor && cause instanceof ApiError && cause.status === 400) {
        cursors.value = [''];
        clearTimeout(timer);
        if (read === controller) {
          read = undefined;
          pending.value = false;
        }
        return refresh(true);
      }
      error.value = controller.signal.aborted
        ? '命中记录读取超时，请重试。'
        : cause instanceof Error
          ? cause.message
          : '命中记录读取失败，请重试。';
    } finally {
      clearTimeout(timer);
      if (read === controller) pending.value = false;
    }
  }
  // 时间窗由调用方按本地时间提交；窗口非法时不发起请求，直接给出可纠正的输入提示。
  function load(listId: string, start: string, end: string) {
    if (stopped) return;
    read?.abort();
    read = undefined;
    let scope: WatchlistHitQuery;
    try {
      scope = watchlistHitQuery(listId, start, end, '', query.value?.limit ?? defaultPageSize);
    } catch (cause) {
      query.value = null;
      cursors.value = [''];
      page.value = empty();
      loaded.value = false;
      pending.value = false;
      error.value = cause instanceof Error ? cause.message : '命中查询窗口无效。';
      return;
    }
    query.value = scope;
    cursors.value = [''];
    page.value = empty();
    loaded.value = false;
    void refresh();
  }
  function next() {
    if (pending.value || !query.value || !page.value.next_cursor) return;
    cursors.value = [...cursors.value, page.value.next_cursor];
    void refresh();
  }
  function previous() {
    if (pending.value || cursors.value.length <= 1) return;
    cursors.value = cursors.value.slice(0, -1);
    void refresh();
  }
  function changePageSize(limit: number) {
    const scope = query.value;
    if (pending.value || !scope || limit === scope.limit) return;
    query.value = { ...scope, cursor: '', limit };
    cursors.value = [''];
    page.value = empty();
    loaded.value = false;
    void refresh();
  }
  const retry = () => (query.value ? refresh() : Promise.resolve());
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
  onScopeDispose(() => {
    stopped = true;
    clear();
  });
  return {
    page: shallowReadonly(page),
    pending: shallowReadonly(pending),
    error: shallowReadonly(error),
    loaded: shallowReadonly(loaded),
    query: shallowReadonly(query),
    cursors: shallowReadonly(cursors),
    load,
    next,
    previous,
    changePageSize,
    retry,
    clear,
  };
}
