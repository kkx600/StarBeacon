<script setup lang="ts">
import {computed,ref} from 'vue'
import {useRoute} from 'vue-router'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import QualityEventsPanel from '../../../web/packages/shared/src/components/QualityEventsPanel.vue'
import QualityEventsFilters from '../../../web/packages/shared/src/components/QualityEventsFilters.vue'
import type {QualityPage} from '../../../web/packages/shared/src/qualityEvents'
import {qualityObservation} from '../data/detectionQuality'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>(),route=useRoute()
const form=ref({start:'2026-10-18T08:00:00',end:'2026-10-18T09:00:00',sensor:'probe_example',registration:'registration_example',kind:''})
const report=qualityObservation().quality!
report.evaluated_at='2026-10-18T00:30:06Z';report.sampled_at='2026-10-18T00:30:05.123456789Z';report.received_at='2026-10-18T00:30:05.923456789Z';report.interval_started_at='2026-10-18T00:30:00.123456789Z'
const original:QualityPage={items:[{schema_version:1,id:'a'.repeat(64),tenant_id:'tenant_example',sensor_id:'probe_example',sensor_registration_id:'registration_example',created_at:'2026-10-18T00:30:06.123456789Z',signal:{kind:'limitation',reasons:['detect.alert_queue_overflow','detect.alerts_suppressed','tcp.stream_depth_reached'],fingerprint:'c'.repeat(64)},report}],page:1,page_size:20,total:'1'}
const result=computed(()=>{
 if(['empty','loading','error'].includes(props.state))return {...original,items:[],total:'0'}
 const p=structuredClone(original),row=p.items[0]!
 if(route.query.result==='reminder')row.signal.reminder=true
 if(route.query.result==='clear'){row.signal={kind:'interval_clear',reasons:['tcp.stream_depth_reached'],fingerprint:'d'.repeat(64),prior_event_id:'b'.repeat(64)};row.report.counters=row.report.counters.map(c=>({...c,...(c.kind==='counter'?{delta:'0'}:{})}));for(const layer of ['capture','inspection','alerting','policy'] as const)row.report[layer]={state:'no_reported_change',reasons:[]}}
 return p
})
</script>
<template>
 <PageHeader title="质量事件" description="按探针、注册代次和时间窗口核对检测区间历史。"><router-link to="/page/sensors"><a-button>探针列表</a-button></router-link></PageHeader>
 <a-alert type="info" show-icon message="以下为合成示例，仅用于演示质量事件检索。此处不查询设备或发送通知。事件仅描述历史区间，不代表探针当前状态或逐流检测覆盖。" class="section-gap"/>
 <QualityEventsFilters v-model="form" :pending="state==='loading'" @query="emit('state','data')" @cancel="emit('state','error')" @reset="emit('state','empty')"/>
 <QualityEventsPanel :result="result" :pending="state==='loading'" :error="state==='error'?'未能完整核对质量事件，本次不提供部分结果。请稍后重试。':''" attempted :initial-i-d="state==='detail'||state==='action'?'a'.repeat(64):undefined" @retry="emit('state','data')" @page="emit('state','data')"/>
</template>
