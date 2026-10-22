<script setup lang="ts">
import {reactive,ref} from 'vue'
import {correlationRequestError,type CorrelationRequest} from '../correlation'
const props=defineProps<{revision:number;windowSeconds:number;initial?:CorrelationRequest;pending:boolean;disabled?:boolean;error?:string}>()
const emit=defineEmits<{run:[query:CorrelationRequest];cancel:[];change:[]}>()
function local(value:number){const d=new Date(value);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,19)}
const step=props.windowSeconds*1000,end=Math.floor(Date.now()/step)*step,start=end-Math.floor(Math.min(3600,Math.max(900,props.windowSeconds*3))/props.windowSeconds)*step
const scope=reactive({start:local(props.initial?Date.parse(props.initial.start):start),end:local(props.initial?Date.parse(props.initial.end):end)}),localError=ref('')
function run(){
 if(props.pending||props.disabled)return
 const start=Date.parse(scope.start),end=Date.parse(scope.end)
 if(!Number.isFinite(start)||!Number.isFinite(end)||local(start)!==(scope.start.length===16?scope.start+':00':scope.start)||local(end)!==(scope.end.length===16?scope.end+':00':scope.end)){localError.value='请选择有效的本机起止时间，精确到秒。';return}
 const query:CorrelationRequest={expected_revision:props.revision,start:new Date(start).toISOString(),end:new Date(end).toISOString()}
 localError.value=correlationRequestError(query)
 if(!localError.value)emit('run',query)
}
function changed(){localError.value='';emit('change')}
</script>
<template><section class="panel panel-body"><a-form :model="scope" layout="vertical" :disabled="pending||disabled" @finish="run"><div class="correlation-scope"><a-form-item label="回测开始时间" html-for="correlation-start" required><a-input id="correlation-start" v-model:value="scope.start" type="datetime-local" step="1" @update:value="changed"/></a-form-item><a-form-item label="回测结束时间" html-for="correlation-end" required><a-input id="correlation-end" v-model:value="scope.end" type="datetime-local" step="1" @update:value="changed"/></a-form-item><div class="correlation-scope-actions"><a-button type="primary" html-type="submit" :loading="pending" :disabled="disabled||pending">运行回测</a-button><a-button v-if="pending" :disabled="false" @click="emit('cancel')">停止等待</a-button></div></div></a-form><a-alert v-if="localError||error" type="error" show-icon :message="error||localError" class="section-gap"/><p class="page-description">起止时间按本机时区显示，查询使用 UTC 半开区间；单次范围最多一小时。{{windowSeconds}} 秒固定窗口按 UTC 对齐，首尾不完整窗口不计入阈值结果。</p></section></template>
<style scoped>.correlation-scope{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto;column-gap:12px;align-items:end}.correlation-scope .ant-form-item{margin-bottom:8px}.correlation-scope-actions{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}@media(max-width:1100px){.correlation-scope{grid-template-columns:repeat(2,minmax(0,1fr))}.correlation-scope-actions{grid-column:1/-1}}</style>
