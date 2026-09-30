import type {BusinessRecord,MetricSpec} from '../models'

export interface SensorThresholds {cpu:number;memory:number;disk:number;drop:number;heartbeat:number}
export const defaultSensorThresholds:SensorThresholds={cpu:80,memory:85,disk:85,drop:0.1,heartbeat:180}

// 使用固定示例快照计算心跳新鲜度，不能把陈旧资源值当作当前状态。
export function healthFor(record:BusinessRecord,thresholds:SensorThresholds=defaultSensorThresholds):string {
  if(record.status!=='在线'||typeof record.heartbeatAge!=='number'||record.heartbeatAge>thresholds.heartbeat)return '不可观测'
  if(typeof record.disk==='number'&&record.disk>=thresholds.disk)return '磁盘水位高'
  if(typeof record.cpu==='number'&&record.cpu>=thresholds.cpu)return 'CPU 负载高'
  if(typeof record.memory==='number'&&record.memory>=thresholds.memory)return '内存水位高'
  if(record.role!=='执行采集器'&&typeof record.dropPercent==='number'&&record.dropPercent>=thresholds.drop)return '丢包关注'
  if([record.cpu,record.memory,record.disk,...(record.role==='执行采集器'?[]:[record.dropPercent])].some(value=>typeof value!=='number'))return '遥测不完整'
  return '正常'
}

export function sensorMetrics(records:BusinessRecord[],thresholds:SensorThresholds):MetricSpec[] {
  const online=records.filter(record=>record.status==='在线')
  const observed=online.filter(record=>record.role!=='执行采集器'&&healthFor(record,thresholds)!=='不可观测'&&typeof record.bpsMbit==='number')
  return [
    {label:'当前范围探针',value:String(records.length)},
    {label:'在线',value:String(online.length),tone:'success'},
    {label:'需要关注',value:String(records.filter(record=>healthFor(record,thresholds)!=='正常').length),tone:'warning'},
    {label:'观测镜像流量',value:observed.length?String(observed.reduce((total,record)=>total+Number(record.bpsMbit),0)):'—',suffix:observed.length?'Mbit/s':undefined,note:observed.length?`${observed.length} 个探针快照`:'当前范围无捕获遥测'},
  ]
}
