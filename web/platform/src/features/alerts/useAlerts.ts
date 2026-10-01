import { onScopeDispose, shallowRef, watch, shallowReadonly } from 'vue'
import type { SearchRequest, SearchResult } from '@starbeacon/shared/types.ts'
import { session } from '../../session'

export function useAlerts() {
  const now = new Date()
  const query = shallowRef<SearchRequest>({start: new Date(now.getTime() - 86400000).toISOString(), end: now.toISOString(), page: 1, page_size: 20, keyword: '', source_ip: '', destination_ip: '', protocol: '', method: '', path: '', severity: ''})
  const result = shallowRef<SearchResult>({items: [], total: 0, page: 1, page_size: 20}), pending = shallowRef(true), error = shallowRef('')
  let windowHours = 24
  const stop = watch(query, async (_value, _previous, onCleanup) => {
    const controller = new AbortController(); onCleanup(() => controller.abort())
    pending.value = true; error.value = ''
    try {const value = await session.api.request<SearchResult>('/alerts/search', {method: 'POST', body: query.value, signal: controller.signal}); if (!controller.signal.aborted) result.value = value} catch(e) {if (!controller.signal.aborted) error.value = e instanceof Error ? e.message : '检索失败'} finally {if (!controller.signal.aborted) pending.value = false}
  }, {immediate: true})
  onScopeDispose(stop)
  function search(filters: Omit<SearchRequest, 'start'|'end'|'page'|'page_size'>, hours: number) {windowHours = hours; const end = new Date(); query.value = {...filters, start: new Date(end.getTime() - hours*3600000).toISOString(), end: end.toISOString(), page: 1, page_size: 20}}
  function page(value: number, size: number) {query.value = {...query.value, page: value, page_size: size}}
  function refresh() {
    const end = new Date()
    query.value = {...query.value, start: new Date(end.getTime() - windowHours*3600000).toISOString(), end: end.toISOString(), page: 1}
  }
  return {result: shallowReadonly(result), pending: shallowReadonly(pending), error: shallowReadonly(error), search, page, refresh}
}
