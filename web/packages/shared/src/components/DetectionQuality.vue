<script setup lang="ts">
import {computed, onMounted, onScopeDispose, shallowRef} from 'vue'
import {Descriptions as ADescriptions, Table as ATable} from 'ant-design-vue'
import type {CaptureConfig} from '../types'
import {formatTime} from '../types'
import {formatBytes} from '../utils/format'
import {qualityCounters, qualityDisplayState, qualityFacetNames, qualityFacetStates, qualityHelp, qualityStates, readQuality} from '../detectionQuality'
const ADescriptionsItem = ADescriptions.Item
const props = withDefaults(defineProps<{capture?:CaptureConfig; online?:boolean}>(), {online:true})
const now = shallowRef(Date.now())
let timer:ReturnType<typeof setInterval>|undefined
onMounted(() => {timer=setInterval(() => {now.value=Date.now()}, 1000)})
onScopeDispose(() => {clearInterval(timer)})
const report = computed(() => readQuality(props.capture?.quality, props.capture?.config_sha256))
const state = computed(() => report.value ? qualityDisplayState(report.value, props.capture?.status==='running', props.online, now.value) : 'unavailable')
const interval = computed(() => state.value==='observed')
const rows = computed(() => report.value?.counters ?? [])
const facets = computed(() => Object.entries(qualityFacetNames).map(([key,label]) => ({key,label, state:interval.value ? report.value![key as keyof typeof qualityFacetNames].state : 'unknown'})))
const columns = [{title:'原生指标',key:'metric',width:270},{title:'本次进程累计 / 当前值',key:'total',width:205},{title:'区间增量',key:'delta',width:180}]
const number = (value?:string) => value===undefined ? '未提供' : new Intl.NumberFormat('zh-CN').format(BigInt(value))
</script>
<template>
  <a-alert :type="state==='observed'?'info':'warning'" show-icon :message="qualityStates[state]" :description="qualityHelp[state]" class="section-gap" />
  <div class="quality-facets section-gap"><div v-for="facet in facets" :key="facet.key" class="quality-facet"><span>{{facet.label}}</span><strong :class="{'quality-limited':facet.state==='limited','quality-policy':facet.state==='policy_applied'}">{{qualityFacetStates[facet.state as keyof typeof qualityFacetStates]}}</strong></div></div>
  <template v-if="report">
    <a-descriptions size="small" bordered :column="1" class="section-gap">
      <a-descriptions-item label="原生采样时间">{{formatTime(report.sampled_at)}}</a-descriptions-item>
      <a-descriptions-item label="采集器读取时间">{{formatTime(report.received_at)}}</a-descriptions-item>
      <a-descriptions-item label="区间起点">{{interval?formatTime(report.interval_started_at):'未建立可比较区间'}}</a-descriptions-item>
      <a-descriptions-item label="引擎运行标识"><span class="quality-identity">{{report.engine_run_id||'尚未启动'}}</span></a-descriptions-item>
      <a-descriptions-item v-if="report.reset_counters.length" label="复位指标">{{report.reset_counters.map(key=>qualityCounters[key][0]).join('、')}}</a-descriptions-item>
    </a-descriptions>
    <div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="key" size="small" :pagination="false" :scroll="{x:655,y:340}"><template #bodyCell="{column,record}">
      <template v-if="column.key==='metric'"><span>{{qualityCounters[record.key as keyof typeof qualityCounters][0]}}</span><small class="quality-native">{{record.key}}</small></template>
      <template v-else-if="column.key==='total'">{{record.key==='decoder.bytes'&&record.total!==undefined?formatBytes(record.total):number(record.total)}}</template>
      <template v-else-if="column.key==='delta'"><span :class="{'quality-limited':interval&&record.delta!==undefined&&record.delta!=='0'&&['capture','inspection','alerting'].includes(record.layer)&&record.key!=='capture.kernel_packets'}">{{record.kind==='gauge'?'瞬时值，不计算增量':!interval?'不可比较':record.key==='decoder.bytes'&&record.delta!==undefined?formatBytes(record.delta):number(record.delta)}}</span></template>
    </template></a-table></div>
  </template>
  <p class="page-description section-gap">范围为探针采样区间，不能定位到每条会话。策略抑制与旁路单独展示；未覆盖全部 pass、阈值策略和驱动计数。此处不代表事件上报、索引或通知送达质量。</p>
</template>
<style scoped>
.quality-facets{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.quality-facet{border:1px solid var(--line);border-radius:8px;padding:10px;min-width:0}.quality-facet span{display:block;color:var(--muted);font-size:12px}.quality-facet strong{display:block;margin-top:4px;font-size:14px;font-weight:500;overflow-wrap:anywhere}.quality-limited{color:var(--warning)}.quality-policy{color:var(--link)}.quality-native{display:block;font-size:11px;color:var(--muted);overflow-wrap:anywhere}.quality-identity{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}@media(max-width:700px){.quality-facets{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style>
