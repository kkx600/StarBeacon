<script setup lang="ts">
import {Table as ATable} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import type {SensorGroup} from './management'
const props=defineProps<{items:readonly SensorGroup[];admin:boolean;locked:boolean}>()
const emit=defineEmits<{edit:[group:SensorGroup];members:[group:SensorGroup]}>()
const columns=[{title:'分组名称',key:'name',width:220},{title:'分组状态',key:'active',width:100},{title:'探针数量',key:'members',width:120},{title:'说明',dataIndex:'description',width:240,ellipsis:true},{title:'更新时间',key:'updated',width:180},{title:'操作',key:'action',width:180}]
function action(kind:'edit'|'members',id:string){const item=props.items.find(g=>g.id===id);if(!item)return;if(kind==='edit')emit('edit',item);else emit('members',item)}
</script>
<template><div class="table-wrap"><a-table :columns="columns" :data-source="[...items]" row-key="id" :pagination="false" :scroll="{x:1040}"><template #bodyCell="{column,record}">
 <template v-if="column.key==='name'"><span>{{record.name}}</span><small class="record-id technical">{{record.id}} · 修订 {{record.revision}}</small></template>
 <span v-else-if="column.key==='active'" class="status" :class="record.active?'status-online':'status-disabled'">{{record.active?'启用':'停用'}}</span>
 <button v-else-if="column.key==='members'" class="link-button" @click="action('members',record.id)">{{record.member_count}} 台</button>
 <template v-else-if="column.key==='updated'">{{formatTime(record.updated_at)}}</template>
 <template v-else-if="column.key==='action'"><a-space><a-button type="link" @click="action('members',record.id)">查看探针</a-button><a-button v-if="admin" type="link" :disabled="locked" @click="action('edit',record.id)">编辑</a-button></a-space></template>
</template></a-table></div></template>
