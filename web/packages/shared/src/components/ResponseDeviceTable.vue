<script setup lang="ts">
import {onScopeDispose,shallowRef} from 'vue'
import {Table as ATable,Tag as ATag} from 'ant-design-vue'
import type {ResponseDevice} from '../responseDevices'
import {deviceState,usableDevice} from '../responseDevices'
import {formatTime} from '../types'
defineProps<{items:ResponseDevice[]}>()
const emit=defineEmits<{view:[device:ResponseDevice];actions:[device:ResponseDevice];respond:[device:ResponseDevice]}>()
const now=shallowRef(Date.now()),timer=setInterval(()=>{now.value=Date.now()},5000);onScopeDispose(()=>clearInterval(timer))
const columns=[{title:'设备 / 连接器',key:'device',width:215},{title:'执行探针',key:'sensor',width:200},{title:'接口版本',dataIndex:'version',width:160},{title:'当前条件',key:'status',width:175},{title:'最长封禁',key:'ttl',width:110},{title:'设备核验时间',key:'observed',width:185},{title:'操作',key:'actions',width:215}]
</script>
<template><a-table :columns="columns" :data-source="items" :row-key="(v:ResponseDevice)=>v.sensor_id+'/'+v.connector_id" :pagination="false" size="middle" :scroll="{x:1260}"><template #bodyCell="{column,record}"><template v-if="column.key==='device'"><span class="technical">{{record.device_id}}</span><small class="device-secondary">{{record.connector_id}}</small></template><template v-else-if="column.key==='sensor'">{{record.sensor_name}}<small class="device-secondary technical">{{record.sensor_id}}</small></template><a-tag v-else-if="column.key==='status'" :color="usableDevice(record as ResponseDevice,now)?'success':record.status==='unavailable'?'error':undefined">{{deviceState(record as ResponseDevice,now)}}</a-tag><template v-else-if="column.key==='ttl'">{{record.max_ttl_seconds.toLocaleString()}} 秒</template><template v-else-if="column.key==='observed'">{{record.observation==='pending'?'尚未核验':formatTime(record.observed_at)}}</template><div v-else-if="column.key==='actions'" class="table-actions"><a-button type="link" @click="emit('view',record as ResponseDevice)">查看</a-button><a-button type="link" @click="emit('actions',record as ResponseDevice)">相关动作</a-button><a-button type="link" :disabled="!usableDevice(record as ResponseDevice,now)" @click="emit('respond',record as ResponseDevice)">限时封禁</a-button></div></template></a-table></template>
<style scoped>.device-secondary{display:block;color:var(--muted);font-size:12px;overflow-wrap:anywhere}.table-actions{display:flex;flex-wrap:wrap;align-items:center;gap:0}.table-actions .ant-btn{padding-inline:5px}</style>
