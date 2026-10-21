<script setup lang="ts">
import {computed,onMounted,onScopeDispose,shallowRef,watch} from 'vue'
import {Table as ATable,Modal as AModal,Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem,Tag as ATag} from 'ant-design-vue'
import type {ResponseConnector} from '../response'
import {responseStates,readyConnector} from '../response'
import {formatTime} from '../types'
import StatePanel from './StatePanel.vue'
const props=defineProps<{items:readonly ResponseConnector[];detailID?:string}>()
const emit=defineEmits<{close:[]}>()
const selected=shallowRef<ResponseConnector|null>(null)
watch(()=>props.detailID,id=>{selected.value=props.items.find(v=>v.connector_id===id)??null},{immediate:true})
watch(()=>props.items,items=>{if(selected.value)selected.value=items.find(v=>v.connector_id===selected.value?.connector_id)??null})
function view(id:string){selected.value=props.items.find(v=>v.connector_id===id)??null}
function close(){selected.value=null;emit('close')}
const rows=computed(()=>[...props.items])
const columns=[{title:'连接器',dataIndex:'connector_id',width:190},{title:'设备',dataIndex:'device_id',width:190},{title:'接口版本',dataIndex:'version',width:180},{title:'状态',key:'state',width:140},{title:'最长封禁',key:'ttl',width:110},{title:'核验时间',key:'time',width:190},{title:'操作',key:'action',width:80}]
const now=shallowRef(Date.now());let timer:ReturnType<typeof setInterval>|undefined
onMounted(()=>{timer=setInterval(()=>{now.value=Date.now()},5000)})
onScopeDispose(()=>{if(timer)clearInterval(timer)})
function isReady(id:string){const value=props.items.find(item=>item.connector_id===id);return !!value&&readyConnector(value,now.value)}
function status(id:string){const value=props.items.find(item=>item.connector_id===id);return value?.status==='ready'&&!isReady(id)?'观测已过期':responseStates[value?.status??'']??'状态待核查'}
</script>
<template><section class="panel"><div class="panel-header"><h2>联动设备</h2><span>{{items.length}} 个连接器</span></div><div class="panel-body"><a-alert type="info" show-icon message="本机通过私有配置文件登记固定 HTTPS 管理地址和凭据引用。设备身份与原生 TTL 核验后，平台管理员可通过此采集器提交限时联动任务。"/></div><StatePanel :empty="!items.length" description="尚未登记联动设备。请配置采集器的 HTTP 连接器文件，并核对设备接口版本与目标保护范围。"><div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="connector_id" size="small" :pagination="false" :scroll="{x:1080}"><template #bodyCell="{column,record}"><a-tag v-if="column.key==='state'" :color="isReady(record.connector_id)?'success':record.status==='unavailable'?'error':undefined">{{status(record.connector_id)}}</a-tag><template v-else-if="column.key==='time'">{{record.observed_at==='0001-01-01T00:00:00Z'?'尚未核验':formatTime(record.observed_at)}}</template><template v-else-if="column.key==='ttl'">{{record.max_ttl_seconds}} 秒</template><a-button v-else-if="column.key==='action'" type="link" @click="view(record.connector_id)">查看</a-button></template></a-table></div></StatePanel></section><a-modal title="联动设备详情" :open="selected!==null" :width="660" :footer="null" @cancel="close"><template v-if="selected"><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="连接器 / 设备">{{selected.connector_id}} / {{selected.device_id}}</a-descriptions-item><a-descriptions-item label="接口版本">{{selected.version}}</a-descriptions-item><a-descriptions-item label="设备状态">{{status(selected.connector_id)}}</a-descriptions-item><a-descriptions-item label="配置 SHA-256"><span class="technical" style="overflow-wrap:anywhere">{{selected.config_sha256}}</span></a-descriptions-item><a-descriptions-item label="核验时间">{{selected.observed_at==='0001-01-01T00:00:00Z'?'尚未核验':formatTime(selected.observed_at)}}</a-descriptions-item><a-descriptions-item label="最长封禁">{{selected.max_ttl_seconds.toLocaleString()}} 秒</a-descriptions-item></a-descriptions><p class="page-description section-gap">就绪观测超过 35 秒需要重新核对。封禁、回读与解除由主控平台管理员提交签名任务；旁路探针自身不阻断流量。</p><div class="filter-actions"><a-button @click="close">关闭</a-button></div></template></a-modal></template>
