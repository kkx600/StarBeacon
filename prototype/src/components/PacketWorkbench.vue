<script setup lang="ts">
import {computed,ref} from 'vue'
import {CopyOutlined,DownloadOutlined} from '@ant-design/icons-vue'
import {message} from 'ant-design-vue'
import type {PacketRecord} from '../data/fixtures'
import {exportJson} from '../composables/useRecords'
import StatusTag from './StatusTag.vue'
const props=defineProps<{packets:PacketRecord[];compact?:boolean}>()
const selectedId=ref('4');const decode=ref('utf8');const byte=ref(-1);const activeLayer=ref('http')
const packet=computed(()=>props.packets.find(p=>p.id===selectedId.value)??props.packets[0])
const bytes=computed(()=>new TextEncoder().encode(packet.value?.payload??''))
const lines=computed(()=>Array.from({length:Math.ceil(bytes.value.length/16)},(_,row)=>{
  const values=Array.from(bytes.value.slice(row*16,row*16+16));return{offset:(row*16).toString(16).padStart(8,'0'),values,ascii:values.map(v=>v>=32&&v<127?String.fromCharCode(v):'.').join('')}
}))
const decoded=computed(()=>decode.value==='utf8'?new TextDecoder('utf-8',{fatal:false}).decode(bytes.value):Array.from(bytes.value).map(v=>v>=32&&v<127?String.fromCharCode(v):'.').join(''))
const columns=[{title:'序号',dataIndex:'number',width:56},{title:'捕获时间',dataIndex:'time',width:146},{title:'源地址',dataIndex:'source',width:148},{title:'目的地址',dataIndex:'destination',width:145},{title:'协议',dataIndex:'protocol',width:82},{title:'长度',dataIndex:'length',width:72},{title:'摘要',dataIndex:'info'}]
const tree=computed(()=>[
  {title:`帧 ${packet.value?.number??4} · ${packet.value?.length??184} 字节（示例）`,key:'frame',children:[{title:`捕获时间：${packet.value?.time}`,key:'frame-time'},{title:'入站时间：不可观测；出站时间：不可观测',key:'frame-direction'}]},
  {title:'Ethernet II',key:'ethernet',children:[{title:'源 MAC：02:00:00:20:01:18',key:'mac-source'},{title:'目的 MAC：02:00:00:20:01:0f',key:'mac-dest'},{title:'VLAN：20（镜像观测）',key:'vlan'}]},
  {title:'IPv4',key:'ip',children:[{title:`源 IP：${packet.value?.source}`,key:'ip-src'},{title:`目的 IP：${packet.value?.destination}`,key:'ip-dst'},{title:'TTL：64 · 分片：未分片',key:'ip-flags'}]},
  {title:'TCP',key:'tcp',children:[{title:'源端口：51824 · 目的端口：80',key:'tcp-port'},{title:`标志：${packet.value?.flags}`,key:'tcp-flags'},{title:'流：FLOW-20260930-0142',key:'tcp-stream'}]},
  ...(packet.value?.payload?[{title:'HTTP 载荷',key:'http',children:[{title:packet.value.payload.split('\r\n')[0]??'',key:'http-start'},{title:'Host：service.example.test',key:'http-host'},{title:`可显示载荷：${bytes.value.length} 字节`,key:'http-payload'}]}]:[]),
])
async function copy(){try{await navigator.clipboard.writeText(decoded.value);message.success('载荷示例已复制。')}catch{message.info('当前环境不支持复制，请选择文本复制。')}}
</script>
<template>
  <div class="packet-workbench">
    <div class="packet-summary"><a-space><StatusTag value="真实握手示例"/><StatusTag value="双向连续性示例"/><StatusTag value="FIN / ACK 示例"/></a-space><span class="muted">FLOW-20260930-0142 · 8 帧合成示例</span></div>
    <a-table :columns="columns" :data-source="packets" row-key="id" size="small" :pagination="false" :scroll="{x:900}" :row-selection="{type:'radio',selectedRowKeys:[selectedId],onChange:(keys:unknown[])=>{selectedId=String(keys[0]);byte=-1}}" :custom-row="(record:PacketRecord)=>({onClick:()=>{selectedId=record.id;byte=-1},class:record.id===selectedId?'packet-selected':''})"><template #bodyCell="{column,text}"><span :class="{mono:['time','source','destination'].includes(column.dataIndex)}">{{text}}</span></template></a-table>
    <div class="packet-lower">
      <section class="protocol-pane"><div class="pane-heading"><b>协议层</b><span class="muted">按观测来源展示</span></div><a-tree :tree-data="tree" :default-expanded-keys="['frame','ethernet','ip','tcp','http']" :selected-keys="[activeLayer]" @select="(keys:(string|number)[])=>{activeLayer=String(keys[0]);byte=activeLayer.startsWith('http')?0:-1}" block-node/><div class="layer-help">MAC 来自镜像帧，不代表远端主机的物理地址。载荷偏移从应用载荷开始。</div></section>
      <section class="payload-pane"><div class="pane-heading"><b>HEX 载荷</b><a-space><span class="muted">{{byte>=0?`偏移 0x${byte.toString(16)}`:`${bytes.length} 字节`}}</span><a-button size="small" type="text" aria-label="导出载荷示例" @click="exportJson('payload',{source:'synthetic',packet:packet?.id,bytes:Array.from(bytes)})"><DownloadOutlined/></a-button></a-space></div><div v-if="lines.length" class="hex-view"><div class="hex-legend"><span>偏移</span><span>十六进制</span><span>ASCII</span></div><div v-for="(line,row) in lines" :key="line.offset" class="hex-row"><span class="hex-offset">{{line.offset}}</span><span class="hex-bytes"><button v-for="(value,col) in line.values" :key="col" :class="{selected:byte===row*16+col}" :aria-label="`字节偏移 ${row*16+col}：${value.toString(16)}`" @click="byte=row*16+col;activeLayer='http'">{{value.toString(16).padStart(2,'0')}}</button></span><span class="hex-ascii">{{line.ascii}}</span></div></div><div v-else class="no-payload">当前帧无应用载荷。握手标志可在 TCP 协议层查看。</div><div class="pane-heading decode-heading"><b>尝试解码</b><a-space><a-segmented v-model:value="decode" size="small" :options="[{label:'UTF-8',value:'utf8'},{label:'ASCII',value:'ascii'}]"/><a-button type="text" size="small" aria-label="复制解码文本" @click="copy"><CopyOutlined/></a-button></a-space></div><pre class="decoded-text">{{decoded||'当前帧无可解码载荷。'}}</pre><small class="decode-note">UTF-8 解码失败的字节以替换字符显示；原始字节保持不变。TLS 密文不进行推定解码。</small></section>
    </div>
  </div>
</template>
