<script setup lang="ts">
import {shallowRef,watch,computed} from 'vue'
import {Modal as AModal,Descriptions as ADescriptions,Select as ASelect} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {details,inventoryNames,type InventoryRecord} from './inventory'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{record:InventoryRecord|null}>()
const emit=defineEmits<{close:[]}>()
const records=shallowRef<InventoryRecord[]>([]),selectedRevision=shallowRef<number|undefined>(),pending=shallowRef(false),error=shallowRef(''),tick=shallowRef(0)
const selected=computed(()=>records.value.find(record=>record.revision===selectedRevision.value)??props.record)
watch(()=>({id:props.record?.id,kind:props.record?.kind,tick:tick.value}),async(value,_old,onCleanup)=>{
  records.value=[];selectedRevision.value=props.record?.revision;error.value='';pending.value=false;if(!value.id||!value.kind)return
  const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true
  try{const result=await session.api.request<{items:InventoryRecord[]}>(`/inventory/${value.kind}/${value.id}/history`,{signal:controller.signal});if(!controller.signal.aborted)records.value=result.items}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'历史修订读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
},{immediate:true})
</script>
<template>
  <a-modal :title="record?`${inventoryNames[record.kind]}详情`:'对象详情'" :open="record!==null" :width="760" :footer="null" @cancel="emit('close')">
    <div v-if="record&&selected" class="detail-content">
      <a-alert v-if="error" type="error" :message="error" show-icon class="section-gap"><template #action><a-button size="small" @click="tick++">重试</a-button></template></a-alert>
      <div class="revision-picker"><label for="inventory-revision">历史修订</label><a-select id="inventory-revision" v-model:value="selectedRevision" :loading="pending" :options="(records.length?records:[record]).map(row=>({value:row.revision,label:`修订 ${row.revision} · ${formatTime(row.updated_at)}`}))" /></div>
      <p class="page-description section-gap">历史快照默认保留 180 天，每次最多读取 100 个修订；当前有效配置持续保留。</p>
      <a-descriptions bordered :column="1" size="small"><a-descriptions-item v-for="field in details(selected)" :key="field.label" :label="field.label"><span class="inventory-value">{{field.value}}</span></a-descriptions-item><a-descriptions-item label="生效时间">{{formatTime(selected.updated_at)}}</a-descriptions-item><a-descriptions-item label="对象标识"><span class="technical">{{record.id}}</span></a-descriptions-item></a-descriptions>
    </div>
  </a-modal>
</template>
<style scoped>.revision-picker {display:grid;grid-template-columns:auto minmax(0,1fr);align-items:center;gap:var(--field-gap);margin-bottom:var(--related-gap)}.inventory-value {white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:600px){.revision-picker {grid-template-columns:minmax(0,1fr)}}</style>
