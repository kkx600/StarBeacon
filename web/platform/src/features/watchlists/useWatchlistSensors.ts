import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import type {WatchlistSensor} from '@starbeacon/shared/watchlists.ts'
import {session} from '../../session'

export function useWatchlistSensors(){
 const items=shallowRef<WatchlistSensor[]>([]),pending=shallowRef(false),error=shallowRef('')
 let read:AbortController|undefined,stopped=false
 function clear(){read?.abort();read=undefined;items.value=[];pending.value=false;error.value=''}
 async function refresh(){
  if(stopped||session.current.value?.role!=='admin')return
  read?.abort();const controller=new AbortController();read=controller;pending.value=true;error.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{const value=await readSensorDirectory(session.api,controller.signal);if(!controller.signal.aborted&&read===controller)items.value=value.filter(v=>v.active).map(v=>({sensor_id:v.id,registration_id:v.registration_id,name:v.name,available:true}))}
  catch(cause){if(!stopped&&read===controller){items.value=[];error.value=controller.signal.aborted?'探针目录读取超时，请重试。':cause instanceof Error?cause.message:'探针目录读取失败。'}}finally{clearTimeout(timer);if(read===controller)pending.value=false}
 }
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),clear,{flush:'sync'})
 onScopeDispose(()=>{stopped=true;clear()})
 return {items:shallowReadonly(items),pending:shallowReadonly(pending),error:shallowReadonly(error),refresh}
}
