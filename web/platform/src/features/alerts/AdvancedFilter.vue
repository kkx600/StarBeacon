<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef } from 'vue'
import { Modal as AModal, Table as ATable } from 'ant-design-vue'
import { session } from '../../session'

export interface SearchField {name: string; label: string; type: string; aliases: string[]; operators: string[]}
const model = defineModel<string>({required: true})
const props=withDefaults(defineProps<{disabled: boolean;dataset?:'alerts'|'context'}>(),{dataset:'alerts'})
const fields = shallowRef<SearchField[]>([]), fieldError = shallowRef(''), open = shallowRef(false), keyword = shallowRef('')
let controller: AbortController | undefined, stopped = false
const columns = [{title:'字段',dataIndex:'name',width:200},{title:'业务含义',dataIndex:'label',width:160},{title:'类型',dataIndex:'type',width:100},{title:'别名',dataIndex:'aliases',width:180},{title:'支持运算',dataIndex:'operators',width:200}]
const matches = computed(() => fields.value.filter(field => [field.name, field.label, ...field.aliases].join(' ').toLowerCase().includes(keyword.value.trim().toLowerCase())))
async function loadFields() {
  if(stopped)return
  controller?.abort()
  const current=new AbortController();controller=current
  fieldError.value = ''
  try {const value = await session.api.request<{fields:SearchField[]}>(props.dataset==='context'?'/traffic/fields':'/search/fields', {signal:current.signal}); if(!current.signal.aborted) fields.value=value.fields}
  catch(e) {if(!current.signal.aborted) fieldError.value=e instanceof Error ? e.message : '字段目录读取失败'}
}
function insert(name: string) {const field=fields.value.find(value=>value.name===name);if(!field)return;model.value += `${model.value.trim() ? ' and ' : ''}${field.name}${field.type==='protocol' ? '' : ' == '}`; open.value=false }
onMounted(loadFields)
onScopeDispose(() => {stopped=true;controller?.abort()})
</script>
<template>
  <div class="advanced-filter">
    <div class="advanced-label"><label for="alert-display-filter">高级过滤表达式</label><a-button size="small" :disabled="disabled" @click="open=true">字段目录</a-button></div>
    <a-textarea id="alert-display-filter" v-model:value="model" :disabled="disabled" :maxlength="4096" :auto-size="{minRows:2,maxRows:5}" class="technical" placeholder='tcp.port in {80 443} and http.request.uri contains "/api"' />
    <p class="page-description">作用于{{dataset==='context'?'协议事件':'告警'}}索引。支持 and／or／not、括号、比较、contains、in 与端口范围；尚未提供原生逐包检索。</p>
    <a-modal :title="dataset==='context'?'流量检索字段':'告警检索字段'" :open="open" :width="960" :footer="null" @cancel="open=false">
      <a-input v-model:value="keyword" aria-label="查找检索字段" placeholder="字段、别名或业务含义" allow-clear class="section-gap" />
      <a-alert v-if="fieldError" :message="fieldError" type="error" show-icon class="section-gap"><template #action><a-button size="small" @click="loadFields">重试</a-button></template></a-alert>
      <a-table :data-source="matches" :columns="columns" :pagination="{pageSize:10,showSizeChanger:false}" :scroll="{x:840}" row-key="name" size="small">
        <template #bodyCell="{column,record}"><button v-if="column.dataIndex==='name'" class="link-button technical" @click="insert(record.name)">{{record.name}}</button><span v-else-if="column.dataIndex==='aliases' || column.dataIndex==='operators'" class="technical">{{record[column.dataIndex].join('、') || '—'}}</span></template>
      </a-table>
    </a-modal>
  </div>
</template>
<style scoped>
.advanced-filter {grid-column:1/-1;min-width:0;margin-bottom:var(--panel-inset)}
.advanced-label {display:flex;justify-content:space-between;align-items:center;gap:var(--related-gap);margin-bottom:var(--related-gap)}
.advanced-filter .page-description {margin:var(--label-gap) 0 0;line-height:1.6}
</style>
