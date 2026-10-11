<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import AdvancedFilter from '../alerts/AdvancedFilter.vue'
import {session} from '../../session'
import {defaultTrafficFilters,trafficKinds,type TrafficFilters} from './traffic'
import type {SavedDefinition} from '../search/savedSearch'
const props=defineProps<{pending:boolean;applied?:SavedDefinition;fixed?:boolean}>(),emit=defineEmits<{search:[filters:TrafficFilters,hours:number]}>()
const form=reactive({...defaultTrafficFilters(),hours:24}),advanced=shallowRef(false),checking=shallowRef(false),error=shallowRef('')
const disabled=computed(()=>props.pending||checking.value),kindOptions=[{label:'全部协议记录',value:''},...Object.entries(trafficKinds).map(([value,label])=>({value,label}))]
let controller:AbortController|undefined,stopped=false
watch(()=>props.applied,value=>{if(!value)return;controller?.abort();checking.value=false;error.value='';for(const key of Object.keys(defaultTrafficFilters()) as (keyof TrafficFilters)[])form[key]=value.terms[key];form.hours=value.window.mode==='absolute'?0:value.window.hours;advanced.value=value.mode==='advanced'})
async function submit(){
 if(disabled.value||stopped)return
 error.value='';checking.value=true
 const current=new AbortController();controller=current
 try{if(form.filter){const value=await session.api.request<{valid:boolean}>('/search/validate',{method:'POST',body:{filter:form.filter},signal:current.signal});if(!value.valid)throw new Error('高级过滤表达式未通过校验')};if(!current.signal.aborted){const {hours,...filters}=form;emit('search',{...filters},hours)}}
 catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'过滤表达式校验失败'}
 finally{if(!current.signal.aborted)checking.value=false}
}
function reset(){if(disabled.value)return;Object.assign(form,defaultTrafficFilters(),{hours:24});error.value='';emit('search',defaultTrafficFilters(),24)}
onScopeDispose(()=>{stopped=true;controller?.abort()})
</script>
<template>
 <section class="panel section-gap"><a-form :model="form" layout="vertical" @finish="submit"><div class="traffic-filters">
  <a-form-item label="记录类型"><a-select v-model:value="form.event_kind" aria-label="记录类型" :disabled="disabled" :options="kindOptions"/></a-form-item>
  <a-form-item label="时间范围"><a-select v-model:value="form.hours" aria-label="时间范围" :disabled="disabled" :options="[...(props.fixed?[{label:'固定时间范围',value:0}]:[]),{label:'最近 24 小时',value:24},{label:'最近 7 天',value:168},{label:'最近 30 天',value:720}]"/></a-form-item>
  <a-form-item label="源 IP"><a-input v-model:value="form.source_ip" aria-label="源 IP" :disabled="disabled" :maxlength="64" allow-clear/></a-form-item>
  <a-form-item label="目的 IP"><a-input v-model:value="form.destination_ip" aria-label="目的 IP" :disabled="disabled" :maxlength="64" allow-clear/></a-form-item>
  <a-form-item label="协议"><a-input v-model:value="form.protocol" aria-label="协议" :disabled="disabled" :maxlength="32" placeholder="http、tls、tcp 等" allow-clear/></a-form-item>
  <a-form-item label="探针标识"><a-input v-model:value="form.sensor_id" aria-label="探针标识" :disabled="disabled" :maxlength="64" allow-clear/></a-form-item>
  <a-form-item label="探针注册标识"><a-input v-model:value="form.sensor_registration_id" aria-label="探针注册标识" :disabled="disabled" :maxlength="64" allow-clear/></a-form-item>
  <a-form-item label="采集实例标识"><a-input v-model:value="form.source_generation_id" aria-label="采集实例标识" :disabled="disabled" :maxlength="64" allow-clear/></a-form-item>
  <a-form-item label="流标识"><a-input v-model:value="form.flow_id" aria-label="流标识" :disabled="disabled" :maxlength="20" allow-clear/></a-form-item>
  <a-form-item label="HTTP 方法"><a-input v-model:value="form.method" aria-label="HTTP 方法" :disabled="disabled" :maxlength="16" placeholder="GET、POST 等" allow-clear/></a-form-item>
  <a-form-item label="HTTP 路径前缀"><a-input v-model:value="form.path" aria-label="HTTP 路径前缀" :disabled="disabled" :maxlength="1024" allow-clear/></a-form-item>
 </div><AdvancedFilter v-if="advanced" v-model="form.filter" dataset="context" :disabled="disabled"/>
 <a-alert v-if="error" type="error" :message="error" show-icon class="section-gap"/>
 <div class="filter-actions"><a-button type="primary" html-type="submit" :disabled="props.pending" :loading="checking">检索</a-button><a-button :disabled="disabled" @click="reset">重置</a-button><a-button :disabled="disabled" @click="advanced=!advanced">{{advanced?'收起高级检索':'高级检索'}}</a-button></div>
 </a-form></section>
</template>
<style scoped>.traffic-filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0 12px}</style>
