<script setup lang="ts">
import {shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import DetectionQuality from '../../../web/packages/shared/src/components/DetectionQuality.vue'
import {qualityObservation} from '../data/detectionQuality'
const props=defineProps<{open:boolean}>()
const emit=defineEmits<{close:[]}>()
type Mode='observed'|'unavailable'|'counter_reset'|'stale'|'offline'|'refresh_error'
const mode=shallowRef<Mode>('observed'),capture=shallowRef(qualityObservation())
const options=[{value:'observed',label:'区间观测'},{value:'unavailable',label:'尚未观测'},{value:'counter_reset',label:'计数复位'},{value:'stale',label:'观测过期'},{value:'offline',label:'探针离线'},{value:'refresh_error',label:'刷新失败'}]
function select(value:Mode){mode.value=value;capture.value=qualityObservation(value==='offline'||value==='refresh_error'?'observed':value)}
watch(()=>props.open,open=>{if(open)select('observed')})
</script>
<template><a-modal title="检测质量" :open="open" :width="860" @cancel="emit('close')"><a-alert type="info" show-icon message="当前为合成示例，不表示设备实测结果。" class="section-gap"/><div class="quality-example-control section-gap"><label for="quality-example-state">观测状态</label><a-select id="quality-example-state" aria-label="示例观测状态" :value="mode" :options="options" @change="value=>select(value as Mode)"/></div><a-alert v-if="mode==='refresh_error'" type="warning" show-icon message="刷新失败，保留上次观测" description="采集器管理服务暂时无法访问。请重试刷新观测；累计值、采样时间和区间均未更新。" class="section-gap"/><DetectionQuality v-if="open" :capture="capture" :online="mode!=='offline'"/><template #footer><a-button @click="select(mode)">刷新示例</a-button><a-button @click="emit('close')">关闭</a-button></template></a-modal></template>
<style scoped>.quality-example-control{display:flex;align-items:center;gap:12px}.quality-example-control .ant-select{width:180px}</style>
