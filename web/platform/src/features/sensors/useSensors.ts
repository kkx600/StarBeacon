import { onMounted, onScopeDispose, shallowRef, shallowReadonly, watch } from 'vue'
import type { Sensor } from '@starbeacon/shared/types.ts'
import {validSensor} from '@starbeacon/shared/sensors.ts'
import { session } from '../../session'

export function useSensors() {
  const items = shallowRef<Sensor[]>([]), pending = shallowRef(true), error = shallowRef(''), saving = shallowRef(false)
  const nextCursor=shallowRef(''),cursors=shallowRef([''])
  let keyword='',groupID='',status=''
  let controller: AbortController | undefined
  let mutation: AbortController | undefined
  let disposed = false
  async function refresh() {
    if(disposed)return
    controller?.abort(); const active = new AbortController(); controller = active
    pending.value = true; error.value = ''
    try {
      const cursor=cursors.value.at(-1)??''
      const result = await session.api.request<{items: Sensor[];next_cursor?:string}>('/sensors?'+new URLSearchParams({cursor,keyword,group_id:groupID,status,limit:'20'}), {signal: active.signal})
      if (!active.signal.aborted) {
        const next=result.next_cursor??''
        if(!Array.isArray(result.items)||result.items.length>20||typeof next!=='string'||result.items.some((s,i)=>!validSensor(s)||s.id<=cursor||i>0&&s.id<=result.items[i-1]!.id)||next&&(!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(next)||next<=cursor||next!==result.items.at(-1)?.id))throw new Error('探针列表未能完整返回，请刷新后核对。')
        items.value = result.items;nextCursor.value=next
      }
    } catch (e) {if (!active.signal.aborted) error.value = e instanceof Error ? e.message : '读取失败'} finally {if (controller === active) pending.value = false}
  }
  async function toggle(sensor: Sensor) {
    if(saving.value || disposed) return false
    const active = new AbortController(); mutation = active; saving.value = true
    try {await session.api.request(`/sensors/${encodeURIComponent(sensor.id)}`, {method: 'PATCH', body: {active: !sensor.active}, signal: active.signal}); if(active.signal.aborted) return false; await refresh(); return !active.signal.aborted}
    finally {if(mutation === active) saving.value = false}
  }
  onMounted(refresh); onScopeDispose(() => {disposed = true; controller?.abort(); mutation?.abort()})
  watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),()=>{controller?.abort();mutation?.abort();items.value=[];nextCursor.value='';cursors.value=[''];keyword='';groupID='';status='';saving.value=false;if(session.current.value)void refresh()})
  function search(k:string,g:string,s:string){keyword=k.trim();groupID=g;status=s;cursors.value=[''];void refresh()}
  function next(){if(!pending.value&&nextCursor.value){cursors.value=[...cursors.value,nextCursor.value];void refresh()}}
  function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
  return {items: shallowReadonly(items), pending: shallowReadonly(pending), error: shallowReadonly(error), saving: shallowReadonly(saving), nextCursor:shallowReadonly(nextCursor),cursors:shallowReadonly(cursors),refresh, toggle,search,next,previous}
}
