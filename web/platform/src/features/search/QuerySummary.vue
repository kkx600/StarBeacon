<script setup lang="ts">
import {computed} from 'vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {savedWindowLabel,type SavedDefinition,type SearchTerms} from './savedSearch'
const props=defineProps<{definition:SavedDefinition}>()
const labels:Record<keyof SearchTerms,string>={keyword:'关键词',source_ip:'源 IP',destination_ip:'目的 IP',protocol:'协议',method:'HTTP 方法',path:'路径前缀',severity:'严重级别',filter:'高级过滤表达式',event_kind:'记录类型',sensor_id:'探针标识',sensor_registration_id:'探针注册标识',source_generation_id:'采集实例标识',flow_id:'流标识'}
const fields=computed(()=>Object.entries(props.definition.terms).filter(([,value])=>value).map(([key,value])=>({label:labels[key as keyof SearchTerms],value})))
</script>
<template>
 <dl class="query-summary"><div><dt>查询对象</dt><dd>{{definition.dataset==='alerts'?'告警':'协议记录'}} · {{definition.mode==='advanced'?'高级检索':'条件检索'}}</dd></div><div><dt>时间范围</dt><dd>{{savedWindowLabel(definition.window)}}<template v-if="definition.window.mode==='absolute'"> · {{formatTime(definition.window.start)}} — {{formatTime(definition.window.end)}}</template></dd></div><div><dt>过滤语法</dt><dd>{{definition.parser_version}}</dd></div><div v-for="field in fields" :key="field.label"><dt>{{field.label}}</dt><dd class="query-value">{{field.value}}</dd></div><div v-if="!fields.length"><dt>查询条件</dt><dd>所选时间范围内的全部记录</dd></div></dl>
</template>
<style scoped>.query-summary{margin:12px 0;padding:12px;border:1px solid var(--line);border-radius:6px;background:var(--table-header)}.query-summary>div{display:grid;grid-template-columns:100px minmax(0,1fr);gap:12px;padding:4px 0}.query-summary dt{color:var(--muted)}.query-summary dd{margin:0;color:var(--text);overflow-wrap:anywhere;white-space:pre-wrap}.query-value{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}</style>
