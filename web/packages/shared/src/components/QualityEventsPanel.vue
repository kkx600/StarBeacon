<script setup lang="ts">
import {shallowRef,watch} from 'vue'
import {Modal as AModal,Table as ATable,Tag as ATag} from 'ant-design-vue'
import {qualityCounters} from '../detectionQuality'
import {qualityEventNames,type QualityEvent,type QualityPage} from '../qualityEvents'
import StatePanel from './StatePanel.vue'
import DetectionQuality from './DetectionQuality.vue'
const props=defineProps<{result:QualityPage|null;pending:boolean;error:string;attempted:boolean;initialID?:string}>()
const emit=defineEmits<{retry:[];page:[value:number]}>()
const selected=shallowRef<QualityEvent|null>(null)
watch(()=>[props.result,props.initialID],()=>{selected.value=props.result?.items.find(row=>row.id===props.initialID)??null},{immediate:true})
const columns=[{title:'平台记录时间',key:'created',width:255},{title:'探针 / 注册代次',key:'sensor',width:250},{title:'事件类型',key:'kind',width:220},{title:'区间原因',key:'reasons',width:260},{title:'操作',key:'actions',width:90,fixed:'right' as const}]
const reason=(key:string)=>Object.hasOwn(qualityCounters,key)?qualityCounters[key as keyof typeof qualityCounters][0]:({counter_reset:'计数器复位',sample_gap:'采样中断',stale:'观测过期',stopped:'引擎未运行',continuous_interval:'建立连续观测区间'} as Record<string,string>)[key]??key
</script>
<template>
 <section v-if="!selected" class="panel quality-history"><div class="panel-header"><h2>质量事件</h2><span v-if="result">共 {{BigInt(result.total).toLocaleString('zh-CN')}} 条</span></div>
  <StatePanel :loading="pending" :error="error" :empty="!result||!result.items.length" :description="attempted?'当前范围没有可列出的质量事件。请核对探针管理模式、时间窗口及索引状态；空结果不证明检测完整。':'选择时间窗口与筛选条件后查询。'" @retry="emit('retry')">
   <a-table :columns="columns" :data-source="result?.items??[]" row-key="id" :pagination="false" :scroll="{x:1075}"><template #bodyCell="{column,record}">
    <code v-if="column.key==='created'">{{record.created_at}}</code>
    <template v-else-if="column.key==='sensor'"><strong>{{record.sensor_id}}</strong><small>{{record.sensor_registration_id}}</small></template>
    <template v-else-if="column.key==='kind'"><a-tag :color="record.signal.kind==='limitation'?'warning':record.signal.kind==='policy'?'processing':'default'">{{qualityEventNames[record.signal.kind as keyof typeof qualityEventNames]}}</a-tag><small v-if="record.signal.reminder">持续状态提醒</small></template>
    <span v-else-if="column.key==='reasons'">{{record.signal.reasons.map(reason).join('、')}}</span>
    <a-button v-else-if="column.key==='actions'" type="link" @click="selected=record as QualityEvent">详情</a-button>
   </template></a-table>
   <div class="quality-pages"><a-button :disabled="pending||!result||result.page<=1" @click="emit('page',result!.page-1)">上一页</a-button><span>第 {{result?.page??1}} 页</span><a-button :disabled="pending||!result||result.page>=500||BigInt(result.page*20)>=BigInt(result.total)" @click="emit('page',result!.page+1)">下一页</a-button></div>
  </StatePanel>
 </section>
 <a-modal v-if="selected" open title="质量事件详情" :width="920" @cancel="selected=null">
  <a-alert type="info" show-icon message="历史区间快照" description="详情保留当时的统计区间，不代表探针当前状态。原限制未再报告增量不等于补回丢包或恢复全部检测能力。" class="section-gap"/>
  <dl class="quality-event-facts"><dt>事件类型</dt><dd>{{qualityEventNames[selected.signal.kind]}}<a-tag v-if="selected.signal.reminder">持续状态提醒</a-tag></dd><dt>区间原因</dt><dd>{{selected.signal.reasons.map(reason).join('、')}}</dd><dt>事件标识</dt><dd><code>{{selected.id}}</code></dd><dt>探针 / 注册代次</dt><dd>{{selected.sensor_id}} / {{selected.sensor_registration_id}}</dd><dt>平台记录时间</dt><dd><code>{{selected.created_at}}</code></dd><dt>平台接收时的观测时间</dt><dd><code>{{selected.report.evaluated_at}}</code></dd><dt v-if="selected.signal.prior_event_id">关联先前事件</dt><dd v-if="selected.signal.prior_event_id"><code>{{selected.signal.prior_event_id}}</code></dd></dl>
  <DetectionQuality :capture="{status:'running',config_sha256:selected.report.config_sha256,quality:selected.report}" historical/>
  <template #footer><div class="filter-actions quality-close"><a-button @click="selected=null">返回列表</a-button></div></template>
 </a-modal>
</template>
<style scoped>.quality-history{min-width:0;overflow:hidden}.panel-header{padding:var(--panel-inset);display:flex;align-items:center;justify-content:space-between;gap:8px}.panel-header h2{margin:0;font-size:16px}.quality-history small{display:block;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}.quality-history strong,.quality-history code{overflow-wrap:anywhere;white-space:normal}.quality-history code{font-size:12px}.quality-pages{display:flex;justify-content:flex-end;align-items:center;gap:var(--related-gap);padding:var(--panel-inset)}.quality-event-facts{display:grid;grid-template-columns:155px minmax(0,1fr);gap:8px 12px;margin:12px 0}.quality-event-facts dt{color:var(--muted)}.quality-event-facts dd{margin:0;overflow-wrap:anywhere}.quality-close{justify-content:flex-end}@media(max-width:700px){.quality-event-facts{grid-template-columns:minmax(0,1fr);gap:4px}.quality-event-facts dd{margin-bottom:8px}}</style>
