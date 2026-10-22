<script setup lang="ts">
import {computed} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import {useRoute,useRouter} from 'vue-router'
import type {BusinessRecord} from '../models'
import PacketInspector from '../../../web/packages/shared/src/components/PacketInspector.vue'
import {PacketExampleClient,packetExampleLayers,packetExampleRecord,emptyPacketExampleRecord} from '../data/packetInspectionPreview'
import {packetPreviewLocation,selectPacketLayer,selectPacketPreview,type PacketPreviewMode} from '../composables/packetPreview'

const props=defineProps<{open:boolean;record?:BusinessRecord;selectionError?:string}>()
const emit=defineEmits<{close:[]}>()
const route=useRoute(),router=useRouter()
const location=computed(()=>{const value=packetPreviewLocation(route.query,packetExampleLayers);return props.selectionError?{...value,mode:'error' as const,error:props.selectionError}:value})
const client=new PacketExampleClient(()=>location.value)
const record=computed(()=>!props.open?null:location.value.mode==='empty'?emptyPacketExampleRecord:packetExampleRecord)
const states=[{value:'data',label:'有数据'},{value:'loading',label:'加载中'},{value:'error',label:'读取失败'},{value:'empty',label:'无可查看报文'},{value:'expired',label:'归档到期'},{value:'corrupt',label:'摘要不一致'}]
function select(number:number){
 if(number===location.value.number)return
 void router.replace({query:selectPacketPreview(route.query,number),hash:route.hash})
}
function layers(value:number[]){
 const next=value[0]??null
 if(next===location.value.layer)return
 void router.replace({query:selectPacketLayer(route.query,value),hash:route.hash})
}
function state(mode:PacketPreviewMode){
 void router.replace({query:{...route.query,inspect:'packet',packet:String(location.value.number),layer:location.value.layer===null?'none':String(location.value.layer),inspection:mode},hash:route.hash})
}
</script>
<template>
 <PacketInspector :key="`${location.mode}:${location.error}`" :api="client" :record="record" :initial-number="location.number" :initial-layer="location.layer" @close="emit('close')" @select="select" @layers="layers">
  <template #notice>
   <a-alert type="info" show-icon message="合成原包交互示例" class="example-notice">
    <template #description>
     <p class="example-source">固定九帧 HTTP 样本用于展示逐包查看和字节校验，没有读取所选目录的实际原文，也未连接采集器或对象存储。目录示例：{{props.record?.name??'未选择目录'}}。</p>
     <div class="example-state"><label for="packet-example-state">查看状态示例</label><a-select @keydown.esc.stop id="packet-example-state" :value="location.mode" :options="states" @change="value=>state(value as PacketPreviewMode)"/></div>
    </template>
   </a-alert>
  </template>
 </PacketInspector>
</template>
<style scoped>
.example-notice{margin-bottom:var(--section-gap)}
.example-source{margin:0 0 var(--related-gap);overflow-wrap:anywhere}
.example-state{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap)}
.example-state .ant-select{width:180px}
</style>
