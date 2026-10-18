<script setup lang="ts">
import {Select as ASelect} from 'ant-design-vue'
import {qualityEventNames,type QualityFilters} from '../qualityEvents'
const model=defineModel<QualityFilters>({required:true})
defineProps<{pending:boolean}>()
const emit=defineEmits<{query:[];cancel:[];reset:[]}>()
</script>
<template>
 <a-form :model="model" layout="vertical" class="panel quality-event-form" @finish="emit('query')"><div class="quality-event-fields">
  <a-form-item label="开始时间（本地时间）" html-for="quality-start" required><a-input id="quality-start" v-model:value="model.start" type="datetime-local" step="1"/></a-form-item>
  <a-form-item label="结束时间（本地时间）" html-for="quality-end" required extra="结束时刻不包含在查询内，窗口最多 31 天。"><a-input id="quality-end" v-model:value="model.end" type="datetime-local" step="1"/></a-form-item>
  <a-form-item label="事件类型" html-for="quality-kind"><a-select id="quality-kind" v-model:value="model.kind" aria-label="质量事件类型" :options="[{value:'',label:'全部类型'},...Object.entries(qualityEventNames).map(([value,label])=>({value,label}))]"/></a-form-item>
  <a-form-item label="探针标识" html-for="quality-sensor"><a-input id="quality-sensor" v-model:value="model.sensor" :maxlength="64" placeholder="留空查询全部探针"/></a-form-item>
  <a-form-item label="注册代次" html-for="quality-registration" extra="可核对历史注册；填写时须同时指定探针。"><a-input id="quality-registration" v-model:value="model.registration" :maxlength="64" placeholder="留空包含全部注册代次"/></a-form-item>
 </div><div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button v-if="pending" @click="emit('cancel')">取消查询</a-button><a-button :disabled="pending" @click="emit('reset')">重置</a-button><span class="page-description">每页 20 条 · 最多检索前 10,000 条</span></div></a-form>
</template>
<style scoped>.quality-event-form{padding:var(--panel-inset);margin-bottom:var(--section-gap)}.quality-event-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 var(--field-gap)}.quality-event-fields .ant-form-item{min-width:0}.quality-event-fields .ant-select{width:100%}@media(max-width:1200px){.quality-event-fields{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){.quality-event-fields{grid-template-columns:minmax(0,1fr)}}</style>
