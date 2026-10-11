<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import {session} from '../../session'
import type {InventoryPage,InventoryRecord} from './inventory'
const model=defineModel<string>({required:true})
defineProps<{disabled:boolean;inputId?:string}>()
const keyword=shallowRef(''),records=shallowRef<InventoryRecord[]>([]),selected=shallowRef<InventoryRecord|null>(null),pending=shallowRef(true),listError=shallowRef(''),selectedError=shallowRef(''),tick=shallowRef(0)
const error=computed(()=>[listError.value,selectedError.value].filter(Boolean).join('；'))
const options=computed(()=>Array.from(new Map([...(selected.value?[selected.value]:[]),...records.value].map(record=>[record.id,{value:record.id,label:record.data.name,disabled:!record.data.active}])).values()))
watch(()=>({keyword:keyword.value,tick:tick.value}),async(value,_previous,onCleanup)=>{
  const controller=new AbortController(),timer=setTimeout(async()=>{
    pending.value=true;listError.value=''
    try{const result=await session.api.request<InventoryPage>(`/inventory/groups?${new URLSearchParams({keyword:value.keyword,limit:'100'})}`,{signal:controller.signal});if(!controller.signal.aborted)records.value=result.items}
    catch(e){if(!controller.signal.aborted)listError.value=e instanceof Error?e.message:'资产组读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },250)
  onCleanup(()=>{clearTimeout(timer);controller.abort()})
},{immediate:true})
watch(model,async(id,_previous,onCleanup)=>{
  selected.value=null;selectedError.value='';if(!id)return
  const controller=new AbortController();onCleanup(()=>controller.abort())
  try{const record=await session.api.request<InventoryRecord>(`/inventory/groups/${encodeURIComponent(id)}`,{signal:controller.signal});if(!controller.signal.aborted)selected.value=record}
  catch(e){if(!controller.signal.aborted)selectedError.value=e instanceof Error?e.message:'关联资产组无法读取'}
},{immediate:true})
</script>
<template>
  <a-select :id="inputId" aria-label="资产组" :value="model||undefined" :options="options" :disabled="disabled" :loading="pending" show-search allow-clear :filter-option="false" placeholder="不分组；输入名称查找资产组" @search="keyword=$event" @change="value=>model=String(value??'')" />
  <div v-if="error" class="group-error" role="alert">{{error}} <button type="button" class="link-button" @click="tick++">重试</button></div>
  <span v-if="records.length===100" class="page-description">最多显示 100 个匹配项，请缩小查找范围。</span>
</template>
<style scoped>.group-error {color:var(--danger);font-size:12px;line-height:1.6;margin-top:var(--label-gap)}</style>
