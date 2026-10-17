<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import InventoryTable from './InventoryTable.vue'
import InventoryForm from './InventoryForm.vue'
import InventoryDetail from './InventoryDetail.vue'
import {inventoryNames,inventoryObjectNames,type InventoryKind,type InventoryRecord,type InventoryData} from './inventory'
import {useInventory} from './useInventory'
const props=defineProps<{kind:InventoryKind}>()
const kind=computed(()=>props.kind),editable=computed(()=>session.current.value?.role==='admin')
const {result,pending,error,saving,saveError,save,cursors,next,previous,search,refresh,clearSaveError}=useInventory(kind)
const keyword=shallowRef(''),editing=shallowRef<InventoryRecord|null>(null),editorOpen=shallowRef(false),selected=shallowRef<InventoryRecord|null>(null)
watch(kind,()=>{editorOpen.value=false;editing.value=null;selected.value=null;keyword.value=''})
function openEditor(record:InventoryRecord|null){editing.value=record;clearSaveError();editorOpen.value=true}
async function saveRecord(data:InventoryData,id:string){const record=editing.value??{id,kind:kind.value,revision:0,data,created_at:'',updated_at:''};if(await save(data,record)){editorOpen.value=false;editing.value=null}}
</script>
<template>
  <header class="page-header"><div><h1>资产管理</h1><p class="page-description">维护资产通信地址、责任范围与网络域，按历史修订核对调查时的配置。</p></div><div class="filter-actions"><a-button :loading="pending" @click="refresh">刷新</a-button><a-button v-if="editable" type="primary" :disabled="saving" @click="openEditor(null)">创建{{inventoryObjectNames[kind]}}</a-button></div></header>
  <a-form :model="{keyword}" class="panel inventory-search" layout="inline" @finish="search(keyword)"><a-form-item label="名称"><a-input v-model:value="keyword" :maxlength="128" placeholder="按名称查找" allow-clear /></a-form-item><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="keyword='';search('')">重置</a-button></a-form>
  <section class="panel"><div class="panel-header"><h2>{{inventoryNames[kind]}}</h2><span>当前页 {{result.items.length}} 条</span></div><StatePanel :loading="pending" :error="error" :empty="result.items.length===0" :description="`当前条件下没有${inventoryNames[kind]}。`" @retry="refresh"><InventoryTable :kind="kind" :records="result.items" :editable="editable" @edit="openEditor" @view="selected=$event" /></StatePanel><div class="inventory-pagination"><a-button :disabled="pending||cursors.length<=1" @click="previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!result.next_cursor" @click="next">下一页</a-button></div></section>
  <InventoryForm v-if="editorOpen" :kind="kind" :record="editing" :pending="saving" :error="saveError" @save="saveRecord" @close="editorOpen=false" />
  <InventoryDetail :record="selected" @close="selected=null" />
</template>
<style scoped>.inventory-search {display:flex;gap:var(--related-gap);flex-wrap:wrap;align-items:center;padding:var(--panel-inset);margin-bottom:var(--section-gap)}.inventory-search .ant-form-item {margin:0}.inventory-pagination {display:flex;justify-content:flex-end;align-items:center;gap:var(--related-gap);padding:var(--panel-inset);flex-wrap:wrap}@media(max-width:700px){.inventory-search .ant-form-item {flex:1 1 100%;min-width:0}}</style>
