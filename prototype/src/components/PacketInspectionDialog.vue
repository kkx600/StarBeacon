<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import type {BusinessRecord} from '../models'
import example from '../data/packetInspectionExample.json'
import ByteViewer from '../../../web/packages/shared/src/components/ByteViewer.vue'
import type {PacketInspection} from '../../../web/packages/shared/src/packetInspection'
import {formatBytes} from '../../../web/packages/shared/src/utils/format'
const props=defineProps<{open:boolean;record?:BusinessRecord}>()
const emit=defineEmits<{close:[]}>()
const number=ref<number|undefined>(1),selected=ref(1)
const packets=example.packets as PacketInspection[]
const data=computed(()=>packets[selected.value-1]!)
const bytes=computed(()=>JSON.stringify({packet:data.value.packet}))
function read(index:number|undefined){if(index!==undefined&&Number.isInteger(index)&&index>=1&&index<=packets.length){selected.value=index;number.value=index}}
function setNumber(value:unknown){number.value=typeof value==='number'?value:undefined}
watch(()=>props.open,()=>{selected.value=1;number.value=1})
</script>
<template>
 <a-modal :open="open" title="原包协议查看" :width="1000" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="emit('close')">
  <a-alert type="info" show-icon message="合成原包交互示例" description="使用固定的九帧 HTTP 样本展示逐包查看；没有读取所选目录的实际原文，也未连接采集器或对象存储。" class="example-notice"/>
  <p class="muted">目录示例：{{record?.name}} · 每次完整核验归档后读取一个包，最多解析 16 层；不推断双向入站／出站时间，不重组应用正文、校验报文校验和或解密 TLS。</p>
  <form class="inspection-toolbar" @submit.prevent="read(number)"><span>共 {{packets.length}} 包</span><label for="example-packet-number">包序号</label><a-input-number id="example-packet-number" :value="number" @update:value="setNumber" :min="1" :max="packets.length" :precision="0"/><a-button html-type="submit" :disabled="number===undefined||number<1||number>packets.length">查看原包</a-button><a-button :disabled="selected<=1" @click="read(selected-1)">上一包</a-button><a-button :disabled="selected>=packets.length" @click="read(selected+1)">下一包</a-button></form>
  <a-descriptions bordered :column="1" size="small"><a-descriptions-item label="样本 / 包序号">{{data.archive_id}} / {{data.number}}</a-descriptions-item><a-descriptions-item label="网卡捕获时间（UTC）"><time class="mono" :datetime="data.captured_at">{{data.captured_at}}</time></a-descriptions-item><a-descriptions-item label="实际捕获 / 原始帧长度">{{formatBytes(data.captured_length)}} / {{formatBytes(data.original_length)}} · 已解析头部</a-descriptions-item><a-descriptions-item label="所选包 SHA-256"><span class="mono digest">{{data.packet_sha256}}</span></a-descriptions-item><a-descriptions-item label="归档原始内容 SHA-256"><span class="mono digest">{{data.raw_sha256}}</span></a-descriptions-item></a-descriptions>
  <section class="example-layers"><h2>协议层</h2><a-collapse :default-active-key="['0']"><a-collapse-panel v-for="(layer,index) in data.layers" :key="String(index)" :header="`${index+1}. ${layer.name} · ${layer.offset===null?'字节范围未确认':`偏移 ${layer.offset} B`} · ${formatBytes(layer.length)}`"><dl v-if="layer.fields.length" class="protocol-fields"><template v-for="field in layer.fields" :key="field.name"><dt class="mono">{{field.name}}</dt><dd class="mono">{{field.value}}</dd></template></dl><p v-else class="muted">该层未提供结构字段；请对照原始字节。载荷名称不代表应用正文已解码。</p></a-collapse-panel></a-collapse></section>
  <ByteViewer :original="bytes" source="frame"/>
 </a-modal>
</template>
<style scoped>
.example-notice{margin-bottom:var(--section-gap)}.inspection-toolbar{display:flex;gap:var(--related-gap);align-items:center;flex-wrap:wrap;margin-bottom:var(--section-gap)}.inspection-toolbar .ant-input-number{width:140px}.example-layers{margin-top:var(--section-gap)}.example-layers h2{margin:0 0 var(--related-gap);font-size:14px}.protocol-fields{display:grid;grid-template-columns:minmax(160px,1fr) minmax(0,2fr);gap:var(--related-gap);margin:0}.protocol-fields dt,.protocol-fields dd{margin:0;overflow-wrap:anywhere}.digest{overflow-wrap:anywhere;word-break:break-word}
</style>
