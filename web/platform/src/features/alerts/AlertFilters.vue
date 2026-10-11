<script setup lang="ts">
import { Select as ASelect, Radio } from 'ant-design-vue'
import { reactive, shallowRef, computed, onScopeDispose,watch } from 'vue'
import type { SearchRequest } from '@starbeacon/shared/types.ts'
import AdvancedFilter from './AdvancedFilter.vue'
import { session } from '../../session'
import type {SavedDefinition} from '../search/savedSearch'
const ARadioGroup = Radio.Group, ARadioButton = Radio.Button
const props=defineProps<{pending: boolean;inherited?:boolean;applied?:SavedDefinition}>()
type Filters = Omit<SearchRequest,'start'|'end'|'page'|'page_size'> & {filter:string}
const emit = defineEmits<{search: [filters: Filters, hours: number]}>()
const defaults: Filters = {keyword:'',source_ip:'',destination_ip:'',protocol:'',method:'',path:'',severity:'',filter:''}
const form = reactive({...defaults}), hours = shallowRef(props.inherited?0:24), mode=shallowRef('visual'), validating=shallowRef(false), error=shallowRef('')
const busy=computed(()=>props.pending||validating.value)
let controller:AbortController|undefined
onScopeDispose(()=>controller?.abort())
watch(()=>props.applied,value=>{if(!value)return;controller?.abort();validating.value=false;error.value='';for(const key of Object.keys(defaults) as (keyof Filters)[])form[key]=value.terms[key];hours.value=value.window.mode==='absolute'?0:value.window.hours;mode.value=value.mode},{immediate:true})
async function submit() {
  if(busy.value) return
  error.value=''
  const filters:Filters=mode.value==='advanced'?{...defaults,filter:form.filter}:{...form,filter:''}
  if(mode.value==='advanced' && filters.filter?.trim()) {
    controller?.abort(); const current=new AbortController(); controller=current; validating.value=true
    try { await session.api.request('/search/validate',{method:'POST',body:{filter:filters.filter},signal:current.signal}) }
    catch(e) {if(!current.signal.aborted) error.value=e instanceof Error?e.message:'过滤表达式校验失败';return}
    finally {if(!current.signal.aborted) validating.value=false}
    if(current.signal.aborted)return
  }
  emit('search',filters,hours.value)
}
function reset() {if(busy.value)return;Object.assign(form,defaults); hours.value = 24;error.value='';emit('search',{...defaults},hours.value)}
</script>
<template>
  <a-form name="alert-filters" class="panel filter-form" :model="form" :disabled="busy" layout="vertical" @finish="submit">
    <div class="filter-mode"><a-radio-group v-model:value="mode" :disabled="busy" aria-label="检索模式"><a-radio-button value="visual">条件检索</a-radio-button><a-radio-button value="advanced">高级检索</a-radio-button></a-radio-group></div>
    <AdvancedFilter v-if="mode==='advanced'" v-model="form.filter" :disabled="busy" />
    <template v-else>
    <a-form-item name="keyword" label="关键词"><a-input v-model:value="form.keyword" placeholder="规则名称" allow-clear :maxlength="256" /></a-form-item>
    <a-form-item name="source_ip" label="源 IP"><a-input v-model:value="form.source_ip" placeholder="完整 IP 地址" allow-clear :maxlength="64" /></a-form-item>
    <a-form-item name="destination_ip" label="目的 IP"><a-input v-model:value="form.destination_ip" placeholder="完整 IP 地址" allow-clear :maxlength="64" /></a-form-item>
    <a-form-item name="protocol" label="协议"><a-input v-model:value="form.protocol" placeholder="http、tcp、udp" allow-clear :maxlength="32" /></a-form-item>
    <a-form-item name="method" label="请求方法"><a-select v-model:value="form.method" :options="[{label:'全部方法',value:''},...['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'].map(value => ({label:value,value}))]" /></a-form-item>
    <a-form-item name="path" label="路径前缀"><a-input v-model:value="form.path" placeholder="/api/" allow-clear :maxlength="1024" /></a-form-item>
    <a-form-item name="severity" label="严重级别"><a-select v-model:value="form.severity" :options="[{label:'全部级别',value:''},{label:'高危',value:'high'},{label:'中危',value:'medium'},{label:'低危',value:'low'},{label:'未知',value:'unknown'}]" /></a-form-item>
    </template>
    <a-form-item label="时间范围" html-for="alert-filters-hours"><a-select id="alert-filters-hours" v-model:value="hours" :options="[...(inherited?[{label:applied?.window.mode==='absolute'?'固定时间范围':'继承统计窗口',value:0}]:[]),{label:'最近 24 小时',value:24},{label:'最近 7 天',value:168},{label:'最近 30 天',value:720}]" /></a-form-item>
    <a-alert v-if="error" :message="error" type="error" show-icon class="filter-error" />
    <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="busy">查询</a-button><a-button :disabled="busy" @click="reset">重置</a-button></div>
  </a-form>
</template>
<style scoped>.filter-mode,.filter-error {grid-column:1/-1;margin-bottom:var(--panel-inset);min-width:0}</style>
