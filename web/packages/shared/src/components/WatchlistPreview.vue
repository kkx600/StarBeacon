<script setup lang="ts">
import {computed,nextTick,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import StatePanel from './StatePanel.vue'
import WatchlistPreviewResultView from './WatchlistPreviewResult.vue'
import {watchlistDefinitionShape,watchlistPreviewError,watchlistScopeKey,type WatchlistRecord,type WatchlistPreviewRequest,type WatchlistPreviewResult} from '../watchlists'
const props=defineProps<{record:WatchlistRecord;result:WatchlistPreviewResult|null;input?:WatchlistPreviewRequest|null;pending:boolean;error:string}>()
const emit=defineEmits<{run:[input:WatchlistPreviewRequest];change:[];close:[]}>()
const form=reactive({scope:watchlistScopeKey(props.record.definition.sensors[0]!),values:''}),localError=shallowRef(''),errorPanel=shallowRef<HTMLDivElement|null>(null)
const options=computed(()=>props.record.definition.sensors.map(s=>({value:watchlistScopeKey(s),label:s.sensor_id+' / '+s.registration_id})))
async function run(){
 if(props.pending)return
 const scope=props.record.definition.sensors.find(s=>watchlistScopeKey(s)===form.scope),values=form.values.split('\n').map(v=>v.trim()).filter(Boolean)
 const input:WatchlistPreviewRequest={definition:watchlistDefinitionShape(props.record.definition),active:props.record.active,targets:scope?values.map(value=>({...scope,type:props.record.definition.match_type==='domain'?'domain':'ip',value})):[]}
 localError.value=!scope&&values.length?'请选择用于匹配核验的探针。':watchlistPreviewError(input)
 if(localError.value){await nextTick();errorPanel.value?.focus();return}emit('run',input)
}
watch(form,()=>{localError.value='';emit('change')},{deep:true})
</script>
<template><a-modal :open="true" title="名单范围核验" :width="820" :body-style="{maxHeight:'calc(100vh - 240px)',overflowY:'auto'}" @cancel="emit('close')"><a-alert type="info" show-icon message="核验当前定义与用户提交的材料，不查询全部历史流量。材料命中与名单当前生效状态分别展示。" class="section-gap"/><p>{{record.name}} · 修订 {{record.revision}}</p><a-form :model="form" layout="vertical" :disabled="pending" @finish="run"><a-form-item label="材料所属探针" html-for="watchlist-test-sensor"><a-select @keydown.esc.stop id="watchlist-test-sensor" v-model:value="form.scope" :options="options"/></a-form-item><a-form-item :label="record.definition.match_type==='domain'?'待核验精确域名':'待核验 IP 地址'" html-for="watchlist-test-values" extra="每行一项，最多 128 项。留空时只核对范围和有效期，不产生匹配结果。"><a-textarea id="watchlist-test-values" v-model:value="form.values" :maxlength="32512" :auto-size="{minRows:2,maxRows:5}" placeholder="填写需要核验的实际值" class="technical"/></a-form-item></a-form><div v-if="localError" ref="errorPanel" role="region" aria-label="名单核验输入错误" tabindex="-1" class="section-gap"><a-alert type="error" show-icon :message="localError"/></div><StatePanel :loading="pending" :error="error" @retry="run"><WatchlistPreviewResultView v-if="result" :result="result" :input="input??undefined"/><p v-else class="page-description">点击“执行核验”查看范围与材料结果。</p></StatePanel><template #footer><a-button @click="emit('close')">关闭</a-button><a-button type="primary" :loading="pending" @click="run">执行核验</a-button></template></a-modal></template>
