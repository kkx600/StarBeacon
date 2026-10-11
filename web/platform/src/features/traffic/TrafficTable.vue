<script setup lang="ts">
import {Table as ATable,type TablePaginationConfig} from 'ant-design-vue'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {endpoint,trafficKinds,type TrafficRecord,type TrafficResult} from './traffic'
const props=defineProps<{result:TrafficResult}>()
const emit=defineEmits<{view:[record:TrafficRecord];page:[value:number,size:number]}>()
const columns=[{title:'记录 / 协议',key:'kind',width:130},{title:'源 / 目的',key:'endpoints',width:240},{title:'流标识 / 探针',key:'flow',width:210},{title:'客户端→服务端',key:'server',width:170},{title:'服务端→客户端',key:'client',width:170},{title:'事件时间',key:'time',width:185},{title:'操作',key:'action',width:80}]
function page(p:TablePaginationConfig){emit('page',p.current??1,p.pageSize??20)}
function view(id:string){const record=props.result.items.find(row=>row.event_id===id);if(record)emit('view',record)}
</script>
<template>
 <div class="table-wrap"><a-table :columns="columns" :data-source="result.items" row-key="event_id" :scroll="{x:1185}" :pagination="{current:result.page,pageSize:result.page_size,total:Math.min(result.total,10000),showSizeChanger:true,pageSizeOptions:['20','50','100'],showTotal:()=>`共 ${result.total.toLocaleString('zh-CN')} 条`}" @change="page"><template #bodyCell="{column,record}">
 <template v-if="column.key==='kind'">{{trafficKinds[record.event.kind]}}<small class="traffic-sub">{{record.network.protocol||record.network.transport||'未观测到'}}</small></template>
 <template v-else-if="column.key==='endpoints'"><span class="technical">{{endpoint(record.source.ip,record.source.port)}}</span><small class="traffic-sub technical">→ {{endpoint(record.destination.ip,record.destination.port)}}</small></template>
 <template v-else-if="column.key==='flow'"><span class="technical">{{record.suricata.flow_id||'未提供'}}</span><small class="traffic-sub technical">{{record.sensor_id}}</small></template>
 <template v-else-if="column.key==='server'">{{formatBytes(record.details.flow?.bytes_to_server)}}<small class="traffic-sub">{{record.details.flow?.packets_to_server||'未获取'}} 包</small></template>
 <template v-else-if="column.key==='client'">{{formatBytes(record.details.flow?.bytes_to_client)}}<small class="traffic-sub">{{record.details.flow?.packets_to_client||'未获取'}} 包</small></template>
 <template v-else-if="column.key==='time'">{{formatTime(record['@timestamp'])}}</template>
 <a-button v-else-if="column.key==='action'" type="link" @click="view(record.event_id)">查看</a-button>
 </template></a-table></div>
</template>
<style scoped>.traffic-sub{display:block;color:var(--muted);overflow-wrap:anywhere;margin-top:4px}.technical{overflow-wrap:anywhere}</style>
