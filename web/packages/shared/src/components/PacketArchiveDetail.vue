<script setup lang="ts">
import {Descriptions as ADescriptions,Modal as AModal} from 'ant-design-vue'
import {computed} from 'vue'
import StatePanel from './StatePanel.vue'
import {packetCapture,packetUnsealed,packetStates,packetCodes,type PacketRecord} from '../packetArchives'
import {formatTime} from '../types'
import {formatBytes} from '../utils/format'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{record:PacketRecord|null;pending:boolean;error:string;local?:boolean}>()
const emit=defineEmits<{close:[];retry:[]}>()
const capture=computed(()=>props.record?packetCapture(props.record):null)
const unsealed=computed(()=>props.record?packetUnsealed(props.record):false)
</script>
<template>
 <a-modal title="原包归档详情" :open="record!==null" :width="880" :footer="null" @cancel="emit('close')">
  <StatePanel :loading="pending" :error="error" @retry="emit('retry')"><div v-if="record&&capture" class="packet-detail">
   <a-alert type="info" show-icon class="section-gap" message="原包切片保存网卡实际收到的通信字节。单个切片不保证包含整条连接；镜像源缺包、捕获中断与网卡卸载均可能影响完整性。"/>
   <a-alert v-if="record.code" type="warning" show-icon class="section-gap" :message="packetCodes[record.code]??'原包尚未确认，请保留原件并核查采集器状态。'"/>
   <a-alert v-if="unsealed" type="info" show-icon class="section-gap" message="原件尚未封存，目录只包含捕获开始时的身份。包数、首尾包时间和完整性计数尚未冻结；该记录不能下载，也不能作为完整通信证据。"/>
   <a-alert v-if="local&&record.state==='confirmed'" type="info" show-icon class="section-gap" message="平台已持久确认，原件已从本机暂存回收。本机只保留确认摘要和捕获目录；完整压缩清单与原件请在主平台查看。"/>
   <a-descriptions bordered :column="1" size="small">
    <a-descriptions-item label="归档 / 状态"><span class="technical">{{record.id}}</span> · {{packetStates[record.state]}}</a-descriptions-item>
    <a-descriptions-item label="探针 / 注册 / 捕获进程"><span class="technical">{{capture.sensor_id}} / {{capture.registration_id}} / {{capture.run_id}}</span></a-descriptions-item>
    <a-descriptions-item label="网卡 / MAC"><span class="technical">{{capture.interface}} / {{capture.interface_mac}}</span></a-descriptions-item>
    <a-descriptions-item label="捕获开始 / 封存时间">{{formatTime(capture.started_at)}} / {{record.state==='capturing'?'正在捕获':unsealed?'尚未封存':formatTime(capture.ended_at)}}</a-descriptions-item>
    <a-descriptions-item label="首包 / 尾包时间"><template v-if="unsealed">尚未冻结</template><template v-else>{{formatTime(capture.first_packet_at)}} / {{formatTime(capture.last_packet_at)}}</template></a-descriptions-item>
    <a-descriptions-item label="包数 / 载荷字节"><template v-if="unsealed">尚未冻结</template><template v-else>{{capture.packets.toLocaleString('zh-CN')}} 包 / {{formatBytes(capture.packet_bytes)}}</template></a-descriptions-item>
    <a-descriptions-item label="截断 / VLAN 卸载"><template v-if="unsealed">尚未冻结</template><template v-else>{{capture.truncated_packets.toLocaleString('zh-CN')}} 包 / {{capture.vlan_offload_packets.toLocaleString('zh-CN')}} 包</template></a-descriptions-item>
    <a-descriptions-item label="内核丢包">{{unsealed?'尚未冻结':capture.counter_state==='observed'?`${capture.kernel_drops} 包`:'未获取可靠计数'}} · 不代表镜像源没有丢包</a-descriptions-item>
    <a-descriptions-item label="捕获过滤器 / 混杂模式"><span class="technical">{{capture.bpf_filter||'未设置'}}</span> / {{capture.promiscuous?'启用':'关闭'}}</a-descriptions-item>
    <a-descriptions-item label="配置摘要"><span class="technical">{{capture.settings_sha256}}</span></a-descriptions-item>
    <a-descriptions-item label="原始 / 存储大小">{{formatBytes(record.manifest?.encoding.raw_bytes??record.raw_bytes)}} / {{formatBytes(record.manifest?.encoding.stored_bytes??record.stored_bytes??record.acknowledgement?.stored_bytes)}}</a-descriptions-item>
    <a-descriptions-item label="压缩方式">{{record.manifest?.encoding.codec??record.codec??(unsealed?'尚未编码':record.state==='confirmed'?'详见主平台归档':'未获取编码信息')}}<template v-if="record.manifest"> · {{record.manifest.encoding.frames.length}} 个独立块</template></a-descriptions-item>
    <a-descriptions-item label="原始内容 SHA-256"><span class="technical">{{record.manifest?.encoding.raw_sha256??record.acknowledgement?.raw_sha256??'尚未确认'}}</span></a-descriptions-item>
    <a-descriptions-item label="存储内容 SHA-256"><span class="technical">{{record.manifest?.encoding.stored_sha256??record.acknowledgement?.stored_sha256??'尚未确认'}}</span></a-descriptions-item>
    <a-descriptions-item label="目录 SHA-256"><span class="technical">{{record.manifest_sha256||'尚未冻结'}}</span></a-descriptions-item>
    <a-descriptions-item label="对象版本"><span class="technical">{{record.object_version??record.acknowledgement?.object_version??'主平台尚未确认'}}</span></a-descriptions-item>
    <a-descriptions-item label="到期时间">{{formatTime(record.expires_at??record.acknowledgement?.expires_at)}}<template v-if="local&&!record.acknowledgement"> · 未确认原件受本机额度约束，无法按平台留存时间回收</template></a-descriptions-item>
   </a-descriptions>
  </div></StatePanel>
 </a-modal>
</template>
<style scoped>.packet-detail .technical{overflow-wrap:anywhere;word-break:break-word}</style>
