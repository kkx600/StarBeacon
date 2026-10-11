<script setup lang="ts">
import {computed,onMounted,onScopeDispose,shallowRef} from 'vue'
import {Table as ATable} from 'ant-design-vue'
import type {ResponseConnector} from '../response'
import {responseStates,readyConnector} from '../response'
import {formatTime} from '../types'
import StatePanel from './StatePanel.vue'
const props=defineProps<{items:readonly ResponseConnector[]}>()
const rows=computed(()=>[...props.items])
const columns=[{title:'连接器',dataIndex:'connector_id',width:190},{title:'设备',dataIndex:'device_id',width:190},{title:'接口版本',dataIndex:'version',width:180},{title:'状态',key:'state',width:140},{title:'最长封禁',key:'ttl',width:110},{title:'核验时间',key:'time',width:190}]
const now=shallowRef(Date.now());let timer:ReturnType<typeof setInterval>|undefined
onMounted(()=>{timer=setInterval(()=>{now.value=Date.now()},5000)})
onScopeDispose(()=>{if(timer)clearInterval(timer)})
function isReady(id:string){const value=props.items.find(item=>item.connector_id===id);return !!value&&readyConnector(value,now.value)}
function status(id:string){const value=props.items.find(item=>item.connector_id===id);return value?.status==='ready'&&!isReady(id)?'观测已过期':responseStates[value?.status??'']??'状态待核查'}
</script>
<template><section class="panel"><div class="panel-header"><h2>联动设备</h2><span>{{items.length}} 个连接器</span></div><div class="panel-body"><a-alert type="info" show-icon message="本机通过私有配置文件登记固定 HTTPS 管理地址和凭据引用。设备身份与原生 TTL 核验后，平台管理员可通过此采集器提交限时联动任务。"/></div><StatePanel :empty="!items.length" description="尚未登记联动设备。请配置采集器的 HTTP 连接器文件，并核对设备接口版本与目标保护范围。"><div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="connector_id" size="small" :pagination="false" :scroll="{x:1000}"><template #bodyCell="{column,record}"><span v-if="column.key==='state'" class="status" :class="isReady(record.connector_id)?'status-online':'status-medium'">{{status(record.connector_id)}}</span><template v-else-if="column.key==='time'">{{formatTime(record.observed_at)}}</template><template v-else-if="column.key==='ttl'">{{record.max_ttl_seconds}} 秒</template></template></a-table></div></StatePanel></section></template>
