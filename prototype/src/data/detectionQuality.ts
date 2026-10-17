import type {CaptureConfig} from '../../../web/packages/shared/src/types'
import {qualityCounters} from '../../../web/packages/shared/src/detectionQuality'
import type {QualityReport,QualityCounterKey} from '../../../web/packages/shared/src/detectionQuality'

// 全部为界面合成示例；不调用真实采集器，也不授予检测质量或性能资格。
export function qualityObservation(state:'observed'|'unavailable'|'counter_reset'|'stale'='observed'):CaptureConfig {
  const now=Date.now(), known=state!=='unavailable', sampled=now-(state==='stale'?60000:1000)
  const values:Partial<Record<QualityCounterKey,string>>={'capture.kernel_packets':'43892017','capture.kernel_drops':'17','decoder.pkts':'43892000','decoder.bytes':'18446744073709551','flow.active':'1824','detect.alert':'218','detect.alert_queue_overflow':'2','detect.alerts_suppressed':'137','tcp.stream_depth_reached':'4'}
  const r:QualityReport={schema_version:1,scope:'sensor_interval',source:'suricata_eve_stats',state,engine_run_id:known?'engine_demonstration':'',config_sha256:known?'b'.repeat(64):'',evaluated_at:new Date(now).toISOString(),sampled_at:known?new Date(sampled).toISOString():undefined,received_at:known?new Date(sampled+500).toISOString():undefined,interval_started_at:state==='observed'?new Date(sampled-5000).toISOString():undefined,reset_counters:state==='counter_reset'?['detect.alert_queue_overflow']:[],
    counters:Object.entries(qualityCounters).map(([key,[,layer,kind]])=>({key:key as QualityCounterKey,layer,kind,...(known?{total:values[key as QualityCounterKey]??'0'}:{}),...(state==='observed'&&kind==='counter'?{delta:key==='detect.alert_queue_overflow'?'2':key==='detect.alerts_suppressed'?'7':key==='tcp.stream_depth_reached'?'1':'0'}:{})})),
    capture:{state:state==='observed'?'no_reported_change':'unknown',reasons:[]},inspection:{state:state==='observed'?'limited':'unknown',reasons:state==='observed'?['tcp.stream_depth_reached']:[]},alerting:{state:state==='observed'?'limited':'unknown',reasons:state==='observed'?['detect.alert_queue_overflow']:[]},policy:{state:state==='observed'?'policy_applied':'unknown',reasons:state==='observed'?['detect.alerts_suppressed']:[]}}
  return {interfaces:['eth1'],managed:true,status:'running',config_sha256:'b'.repeat(64),quality:r}
}
