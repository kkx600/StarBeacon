import { onMounted, onScopeDispose, shallowRef, shallowReadonly } from 'vue'
import type { Sensor } from '@starbeacon/shared/types.ts'
import { session } from '../../session'

export function useSensors() {
  const items = shallowRef<Sensor[]>([]), pending = shallowRef(true), error = shallowRef(''), saving = shallowRef(false)
  let controller: AbortController | undefined
  async function refresh() {
    controller?.abort(); const active = new AbortController(); controller = active
    pending.value = true; error.value = ''
    try {const result = await session.api.request<{items: Sensor[]}>('/sensors', {signal: active.signal}); if (!active.signal.aborted) items.value = result.items} catch (e) {if (!active.signal.aborted) error.value = e instanceof Error ? e.message : '读取失败'} finally {if (controller === active) pending.value = false}
  }
  async function toggle(sensor: Sensor) {saving.value = true; try {await session.api.request(`/sensors/${encodeURIComponent(sensor.id)}`, {method: 'PATCH', body: {active: !sensor.active}}); await refresh()} finally {saving.value = false}}
  onMounted(refresh); onScopeDispose(() => controller?.abort())
  return {items: shallowReadonly(items), pending: shallowReadonly(pending), error: shallowReadonly(error), saving: shallowReadonly(saving), refresh, toggle}
}
