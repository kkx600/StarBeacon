import { computed,onScopeDispose, shallowRef, watch, shallowReadonly } from 'vue'
import type { SearchRequest, SearchResult } from '@starbeacon/shared/types.ts'
import { session } from '../../session'
import {definitionFromQuery} from '../search/savedSearch'

export function useAlerts(initial?:{start?:string;end?:string}) {
  const now = new Date()
  const firstStart=initial?.start?Date.parse(initial.start):NaN,firstEnd=initial?.end?Date.parse(initial.end):NaN
  const initialInherited=Number.isFinite(firstStart)&&Number.isFinite(firstEnd)&&firstEnd>firstStart&&firstEnd-firstStart<=31*86400000
  const fixed=shallowRef<{start:string;end:string}|null>(initialInherited?{start:new Date(firstStart).toISOString(),end:new Date(firstEnd).toISOString()}:null),inherited=computed(()=>!!fixed.value)
  const query = shallowRef<SearchRequest>({start: fixed.value?.start??new Date(now.getTime() - 86400000).toISOString(), end: fixed.value?.end??now.toISOString(), page: 1, page_size: 20, keyword: '', source_ip: '', destination_ip: '', protocol: '', method: '', path: '', severity: ''})
  const result = shallowRef<SearchResult>({items: [], total: 0, page: 1, page_size: 20}), pending = shallowRef(true), error = shallowRef('')
  const windowHours=shallowRef(initialInherited?0:24)
  const stop = watch(query, async (_value, _previous, onCleanup) => {
    const controller = new AbortController(); onCleanup(() => controller.abort())
    pending.value = true; error.value = ''
    try {const value = await session.api.request<SearchResult>('/alerts/search', {method: 'POST', body: query.value, signal: controller.signal}); if (!controller.signal.aborted) result.value = value} catch(e) {if (!controller.signal.aborted) error.value = e instanceof Error ? e.message : '检索失败'} finally {if (!controller.signal.aborted) pending.value = false}
  }, {immediate: true})
  onScopeDispose(stop)
  function search(filters: Omit<SearchRequest, 'start'|'end'|'page'|'page_size'>, hours: number) {windowHours.value = hours===0&&fixed.value?0:[24,168,720].includes(hours)?hours:24;if(windowHours.value!==0)fixed.value=null; const end = new Date(); query.value = {...filters, start: windowHours.value===0?fixed.value!.start:new Date(end.getTime() - windowHours.value*3600000).toISOString(), end: windowHours.value===0?fixed.value!.end:end.toISOString(), page: 1, page_size: 20}}
  function applyQuery(value:SearchRequest,hours:number){windowHours.value=hours;fixed.value=hours===0?{start:value.start,end:value.end}:null;query.value={...value,page:1,page_size:20}}
  function page(value: number, size: number) {query.value = {...query.value, page: value, page_size: size}}
  function refresh() {
    const end = new Date()
    query.value = {...query.value, start: windowHours.value===0?query.value.start:new Date(end.getTime() - windowHours.value*3600000).toISOString(), end: windowHours.value===0?query.value.end:end.toISOString(), page: 1}
  }
  watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{result.value={items:[],total:0,page:1,page_size:20};fixed.value=null;windowHours.value=24;search({keyword:'',source_ip:'',destination_ip:'',protocol:'',method:'',path:'',severity:'',filter:''},24)})
  return {result: shallowReadonly(result), pending: shallowReadonly(pending), error: shallowReadonly(error), appliedQuery:shallowReadonly(query), inherited, range:computed(()=>({start:query.value.start,end:query.value.end})), definition:computed(()=>definitionFromQuery('alerts',query.value,windowHours.value)),search, page, refresh,applyQuery}
}
