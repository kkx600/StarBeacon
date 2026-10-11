<script setup lang="ts">
import {computed,onScopeDispose,ref,shallowRef,useId,watch} from 'vue'
import {Modal as AModal,Descriptions as ADescriptions,Collapse as ACollapse,InputNumber as AInputNumber} from 'ant-design-vue'
import type {ApiClient} from '../api'
import {packetCapture,type PacketRecord} from '../packetArchives'
import {inspectionStates,verifyPacketInspection,type PacketInspection} from '../packetInspection'
import {formatBytes} from '../utils/format'
import StatePanel from './StatePanel.vue'
import ByteViewer from './ByteViewer.vue'
const ADescriptionsItem=ADescriptions.Item,ACollapsePanel=ACollapse.Panel
const props=defineProps<{api:ApiClient;record:PacketRecord|null}>()
const emit=defineEmits<{close:[]}>()
const number=ref<number|undefined>(1),selectedNumber=shallowRef(1),data=shallowRef<PacketInspection|null>(null),pending=shallowRef(false),error=shallowRef(''),numberID=useId()
const total=computed(()=>props.record?packetCapture(props.record).packets:0),byteSource=computed(()=>data.value?JSON.stringify({packet:data.value.packet}):'')
let controller:AbortController|undefined
function inputNumber(value:string){const parsed=/^[1-9][0-9]*$/.test(value)?Number(value):NaN;number.value=Number.isSafeInteger(parsed)?parsed:undefined}
function stop(){controller?.abort();controller=undefined;data.value=null;pending.value=false;error.value=''}
async function read(index:number){
 const record=props.record
 if(!record||pending.value||!Number.isSafeInteger(index)||index<1||index>total.value)return
 stop();selectedNumber.value=index;number.value=index;pending.value=true
 const active=new AbortController();controller=active
 try{
  const raw=await props.api.request<unknown>('/packet-archives/'+encodeURIComponent(record.id)+'/packets/'+index,{signal:active.signal})
  const result=await verifyPacketInspection(raw,record,index)
  if(!active.signal.aborted&&props.record===record)data.value=result
 }catch(e){if(!active.signal.aborted)error.value=e instanceof Error?e.message:'原包无法读取，请稍后重试'}
 finally{if(!active.signal.aborted)pending.value=false}
}
watch(()=>props.record,record=>{stop();number.value=1;selectedNumber.value=1;if(record)void read(1)},{immediate:true})
onScopeDispose(stop)
</script>
<template>
 <a-modal title="原包协议查看" :open="record!==null" :width="1000" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="emit('close')">
  <p class="muted inspector-note">按所选切片的捕获顺序查看，每次完整核验归档后读取一个包；最多解析 16 层。捕获时间不等于双向入站／出站时间，未重组应用正文、校验报文校验和或解密 TLS。</p>
  <form class="inspector-toolbar" @submit.prevent="number!==undefined&&read(number)"><span>共 {{total.toLocaleString('zh-CN')}} 包</span><label :for="numberID">包序号</label><a-input-number :id="numberID" :value="number??''" @input="inputNumber" @update:value="value=>number=typeof value==='number'?value:undefined" :min="1" :max="total||1" :precision="0" :disabled="pending"/><a-button html-type="submit" :disabled="pending||number===undefined||number<1||number>total">查看原包</a-button><a-button :disabled="pending||selectedNumber<=1" @click="read(selectedNumber-1)">上一包</a-button><a-button :disabled="pending||selectedNumber>=total" @click="read(selectedNumber+1)">下一包</a-button></form>
  <StatePanel :loading="pending" :error="error" :empty="!pending&&!error&&!data" description="所选归档没有可查看的原包" @retry="read(selectedNumber)">
   <template v-if="data">
    <a-alert v-if="data.truncated||data.vlan_offload||data.decode_status!=='parsed'" type="warning" show-icon class="section-gap" :message="`${inspectionStates[data.decode_status]}${data.truncated?' · 捕获内容被截断':''}${data.vlan_offload?' · 存在 VLAN 卸载元数据，未向原字节补写标签':''}`"/>
    <a-descriptions bordered :column="1" size="small"><a-descriptions-item label="归档 / 包序号"><span class="technical">{{data.archive_id}}</span> / {{data.number.toLocaleString('zh-CN')}}</a-descriptions-item><a-descriptions-item label="网卡捕获时间（UTC）"><time class="technical" :datetime="data.captured_at">{{data.captured_at}}</time></a-descriptions-item><a-descriptions-item label="实际捕获 / 原始帧长度">{{formatBytes(data.captured_length)}} / {{formatBytes(data.original_length)}} · {{inspectionStates[data.decode_status]}}</a-descriptions-item><a-descriptions-item label="所选包 SHA-256"><span class="technical">{{data.packet_sha256}}</span></a-descriptions-item><a-descriptions-item label="归档原始内容 SHA-256"><span class="technical">{{data.raw_sha256}}</span></a-descriptions-item></a-descriptions>
    <section class="protocol-layers" aria-label="协议层"><h2>协议层</h2><a-collapse :default-active-key="['0']"><a-collapse-panel v-for="(layer,index) in data.layers" :key="String(index)" :header="`${index+1}. ${layer.name} · ${layer.offset===null?'字节范围未确认':`偏移 ${layer.offset} B`} · ${formatBytes(layer.length)}`"><dl v-if="layer.fields.length" class="protocol-fields"><template v-for="field in layer.fields" :key="field.name"><dt class="technical">{{field.name}}</dt><dd class="technical">{{field.value}}</dd></template></dl><p v-else class="muted">该层未提供结构字段；请对照原始字节。载荷名称不代表应用正文已解码。</p></a-collapse-panel></a-collapse></section>
    <ByteViewer :original="byteSource" source="frame"/>
   </template>
  </StatePanel>
 </a-modal>
</template>
<style scoped>
.inspector-note{margin:0 0 var(--section-gap)}
.inspector-toolbar{display:flex;gap:var(--related-gap);align-items:center;flex-wrap:wrap;margin-bottom:var(--section-gap)}
.inspector-toolbar .ant-input-number{width:140px}
.protocol-layers{margin-top:var(--section-gap);min-width:0}
.protocol-layers h2{margin:0 0 var(--related-gap);font-size:14px}
.protocol-fields{display:grid;grid-template-columns:minmax(160px,1fr) minmax(0,2fr);gap:var(--related-gap);margin:0}
.protocol-fields dt,.protocol-fields dd{margin:0;overflow-wrap:anywhere}
.technical{overflow-wrap:anywhere;word-break:break-word}
@media(max-width:1100px){.protocol-fields{grid-template-columns:minmax(130px,1fr) minmax(0,1.5fr)}}
</style>
