import { onScopeDispose, shallowRef, watch } from 'vue'
import { session } from '../../session'
import { readSearchFields, type SearchField } from './filterCompletion'

export function useSearchFields(dataset: () => 'alerts' | 'context') {
  const fields = shallowRef<SearchField[]>([]), error = shallowRef(''), loading = shallowRef(false)
  let controller: AbortController | undefined, stopped = false
  async function reload() {
    if (stopped) return
    controller?.abort()
    const current = new AbortController(); controller = current
    fields.value = []; error.value = ''; loading.value = true
    try {
      const result = await session.api.request<unknown>(dataset() === 'context' ? '/traffic/fields' : '/search/fields', { signal: current.signal })
      if (!current.signal.aborted && !stopped) fields.value = readSearchFields(result)
    } catch (e) {
      if (!current.signal.aborted && !stopped) error.value = e instanceof Error ? e.message : '检索字段目录读取失败'
    } finally {
      if (controller === current && !stopped) loading.value = false
    }
  }
  watch(dataset, reload, { immediate: true })
  onScopeDispose(() => { stopped = true; controller?.abort() })
  return { fields, error, loading, reload }
}
