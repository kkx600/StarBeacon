import {onBeforeUnmount,onMounted,readonly,shallowRef} from 'vue'
import {session} from '../../session'
import {validOverview,type Overview} from './overview'
export function useOverview(){
  const data=shallowRef<Overview|null>(null),pending=shallowRef(false),error=shallowRef(''),hours=shallowRef(24),automatic=shallowRef(false)
  let generation=0,controller:AbortController|undefined,timer:ReturnType<typeof setInterval>|undefined
  async function refresh(){
    if(![24,48,168,720].includes(hours.value))hours.value=24
    const current=++generation
    controller?.abort();controller=new AbortController();pending.value=true;error.value=''
    const end=new Date(Math.floor(Date.now()/60000)*60000),start=new Date(end.getTime()-hours.value*3600000)
    try {const value=await session.api.request<Overview>('/overview',{method:'POST',body:{start:start.toISOString(),end:end.toISOString()},signal:controller.signal});if(current===generation){if(!validOverview(value))throw new Error('态势统计未能完整返回');data.value=value}}
    catch(e){if(current===generation&&!(e instanceof DOMException&&e.name==='AbortError'))error.value=e instanceof Error?e.message:'态势统计未能完整返回'}
    finally{if(current===generation)pending.value=false}
  }
  onMounted(()=>{void refresh();timer=setInterval(()=>{if(automatic.value&&!pending.value&&document.visibilityState==='visible')void refresh()},30000)})
  onBeforeUnmount(()=>{generation++;controller?.abort();if(timer)clearInterval(timer)})
  return{data:readonly(data),pending:readonly(pending),error:readonly(error),hours,automatic,refresh}
}
