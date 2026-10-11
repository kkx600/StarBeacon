<script setup lang="ts">
import {computed} from 'vue'
import {Table as ATable} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {criticalityNames,purposeNames,type InventoryKind,type InventoryRecord} from './inventory'
const props=defineProps<{kind:InventoryKind;records:InventoryRecord[];editable:boolean}>()
const emit=defineEmits<{edit:[record:InventoryRecord];view:[record:InventoryRecord]}>()
const columns=computed(()=>[{title:'名称',key:'name',width:220},...(props.kind==='assets'?[{title:'网络接口',key:'interfaces',width:260},{title:'重要性',key:'criticality',width:90}]:props.kind==='networks'?[{title:'网段',key:'prefix',width:180},{title:'用途',key:'purpose',width:130}]:[{title:'责任人',key:'owner',width:160}]),{title:'状态',key:'active',width:90},{title:'更新时间',key:'updated_at',width:180},{title:'操作',key:'actions',width:110}])
</script>
<template>
  <div class="table-wrap"><a-table :data-source="records" :columns="columns" :pagination="false" :scroll="{x:900}" row-key="id">
    <template #bodyCell="{column,record}">
      <template v-if="column.key==='name'"><button class="link-button" @click="emit('view',record as InventoryRecord)">{{record.data.name}}</button><span class="record-id technical">{{record.id}} · 修订 {{record.revision}}</span></template>
      <span v-else-if="column.key==='active'" :class="['status',record.data.active?'status-online':'status-disabled']">{{record.data.active?'使用中':'已停用'}}</span>
      <span v-else-if="column.key==='updated_at'">{{formatTime(record.updated_at)}}</span>
      <span v-else-if="column.key==='criticality'">{{criticalityNames[record.data.criticality]??'未指定'}}</span>
      <span v-else-if="column.key==='purpose'">{{purposeNames[record.data.purpose]??'未指定'}}</span>
      <div v-else-if="column.key==='interfaces'" class="technical"><div v-for="iface in record.data.interfaces" :key="iface.name">{{iface.name}} · {{iface.ips.join('、')||iface.mac||'无地址'}}</div><span v-if="!record.data.interfaces?.length">未配置</span></div>
      <div v-else-if="column.key==='actions'" class="filter-actions"><button class="link-button" @click="emit('view',record as InventoryRecord)">查看</button><button v-if="editable" class="link-button" @click="emit('edit',record as InventoryRecord)">编辑</button></div>
      <span v-else class="technical">{{record.data[String(column.key)]||'未指定'}}</span>
    </template>
  </a-table></div>
</template>
