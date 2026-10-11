import type {ApiClient} from './api'
import type {Sensor} from './types'

export function validSensor(value:unknown):value is Sensor{
 if(!value||typeof value!=='object'||Array.isArray(value))return false
 const v=value as Record<string,unknown>,id=/^[a-z0-9][a-z0-9_-]{0,63}$/
 return typeof v.id==='string'&&id.test(v.id)&&typeof v.name==='string'&&typeof v.registration_id==='string'&&id.test(v.registration_id)&&typeof v.active==='boolean'&&typeof v.status==='string'&&['online','offline','disabled'].includes(v.status)&&!!v.health&&typeof v.health==='object'&&!Array.isArray(v.health)
}

// 探针选择器读取完整分页目录；不把未结束或重复的分页显示成完整选项。
export async function readSensorDirectory(api:Pick<ApiClient,'request'>,signal:AbortSignal):Promise<Sensor[]>{
 const collected:Sensor[]=[],seen=new Set<string>();let cursor=''
 for(let round=0;round<101;round++){
  if(signal.aborted)throw new DOMException('探针目录读取已取消','AbortError')
  const result=await api.request<{items:Sensor[];next_cursor?:string}>(cursor?'/sensors?'+new URLSearchParams({cursor,limit:'100'}):'/sensors',{signal})
  if(signal.aborted)throw new DOMException('探针目录读取已取消','AbortError')
  const next=result.next_cursor??''
  if(!Array.isArray(result.items)||result.items.length>100||typeof next!=='string'||next&&(!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(next)||result.items.at(-1)?.id!==next||next<=cursor)||result.items.some(s=>!validSensor(s)||seen.has(s.id))||new Set(result.items.map(s=>s.id)).size!==result.items.length)throw new Error('探针目录未能完整返回，请刷新后核对。')
  for(const sensor of result.items){seen.add(sensor.id);collected.push(sensor)}
  if(collected.length>10000)throw new Error('探针目录超过单次读取上限，请缩小管理范围。')
  if(!next)return collected
  cursor=next
 }
 throw new Error('探针目录分页未结束，请刷新后核对。')
}
