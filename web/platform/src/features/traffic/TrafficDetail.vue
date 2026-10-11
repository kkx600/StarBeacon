<script setup lang="ts">
import {Modal as AModal,Descriptions as ADescriptions} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import {trafficKinds,type TrafficRecord} from './traffic'
const ADescriptionsItem=ADescriptions.Item
defineProps<{record:TrafficRecord|null}>();const emit=defineEmits<{close:[]}>()
</script>
<template>
 <a-modal title="流量记录详情" :open="record!==null" :width="880" :footer="null" @cancel="emit('close')"><div v-if="record" class="traffic-detail">
  <a-alert type="info" message="展示实际协议事件与会话摘要。双向计数按引擎客户端／服务端语义记录；事件时间不是网络出站时间，流标识不能单独用于跨探针关联。" show-icon class="section-gap"/>
  <a-alert v-if="record.details.state==='unavailable'" type="warning" message="协议展示元数据无法完整解析，基础事件保留；不以零值补齐缺失的会话计数。" show-icon class="section-gap"/>
  <a-alert v-else-if="record.details.truncated" type="warning" message="展示字段达到长度或数量限制，部分元数据未完整展示；原始事件保持不变。" show-icon class="section-gap"/>
  <a-descriptions bordered :column="1" size="small">
   <a-descriptions-item label="记录类型 / 协议">{{trafficKinds[record.event.kind]}} / {{record.network.protocol||record.network.transport||'未观测到'}}</a-descriptions-item>
   <a-descriptions-item label="事件 / 探针标识"><span class="technical">{{record.event_id}} / {{record.sensor_id}}</span></a-descriptions-item>
   <a-descriptions-item label="流 / 注册 / 来源代次"><span class="technical">{{record.suricata.flow_id||'未提供'}} / {{record.sensor_registration_id||'未提供'}} / {{record.source_generation_id||'未提供'}}</span></a-descriptions-item>
   <a-descriptions-item label="源 IP / MAC">{{record.source.ip||'未观测到'}} / {{record.source.mac||'未观测到'}}</a-descriptions-item>
   <a-descriptions-item label="目的 IP / MAC">{{record.destination.ip||'未观测到'}} / {{record.destination.mac||'未观测到'}}</a-descriptions-item>
   <a-descriptions-item label="会话源侧 MAC 集合">{{record.details.source_macs.join('、')||'未观测到'}}</a-descriptions-item>
   <a-descriptions-item label="会话目的侧 MAC 集合">{{record.details.destination_macs.join('、')||'未观测到'}}</a-descriptions-item>
   <a-descriptions-item label="事件 / 代理观察 / 平台接收时间">{{formatTime(record['@timestamp'])}} / {{formatTime(record.observed_at)}} / {{formatTime(record.received_at)}}</a-descriptions-item>
   <a-descriptions-item label="会话开始 / 结束">{{formatTime(record.details.flow?.start)}} / {{formatTime(record.details.flow?.end)}}</a-descriptions-item>
   <a-descriptions-item label="会话状态 / 结束原因">{{record.details.flow?.state||'未提供'}} / {{record.details.flow?.reason||'未提供'}}</a-descriptions-item>
   <a-descriptions-item label="客户端→服务端">{{formatBytes(record.details.flow?.bytes_to_server)}} · {{record.details.flow?.packets_to_server||'未获取'}} 包</a-descriptions-item>
   <a-descriptions-item label="服务端→客户端">{{formatBytes(record.details.flow?.bytes_to_client)}} · {{record.details.flow?.packets_to_client||'未获取'}} 包</a-descriptions-item>
   <a-descriptions-item label="HTTP 方法 / 主机 / 路径">{{record.http.method||'未提供'}} / {{record.http.hostname||'未提供'}} / {{record.http.path||'未提供'}}</a-descriptions-item>
   <a-descriptions-item label="报文来源 / 方向 / Community ID">{{record.details.packet_source||'未提供'}} / {{record.details.direction||'未提供'}} / <span class="technical">{{record.details.community_id||'未提供'}}</span></a-descriptions-item>
  </a-descriptions>
  <template v-if="record.details.tls"><h2>TLS 可见元数据</h2><a-alert type="info" message="SNI 与证书信息仅说明可见握手元数据，不证明密文已解密；ECH、会话恢复或捕获缺口可能导致字段缺失。" show-icon class="section-gap"/><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="SNI / 版本">{{record.details.tls.sni||'未观测到'}} / {{record.details.tls.version||'未提供'}}</a-descriptions-item><a-descriptions-item label="证书主体 / 签发者">{{record.details.tls.subject||'未观测到'}} / {{record.details.tls.issuer||'未观测到'}}</a-descriptions-item><a-descriptions-item label="源记录证书指纹"><span class="technical">{{record.details.tls.fingerprint||'未提供'}}</span></a-descriptions-item></a-descriptions></template>
  <template v-if="record.details.dns"><h2>DNS 可见元数据</h2><p>日志格式 {{record.details.dns.version||'未提供'}} · {{record.details.dns.type||'未提供'}} · {{record.details.dns.rcode||'未提供'}}</p><ul v-if="record.details.dns.queries.length"><li v-for="(query,index) in record.details.dns.queries" :key="index" class="technical">{{query.name}} · {{query.type}}</li></ul><p v-else class="muted">当前记录未提供可解析的查询数组。</p></template>
  <h2>原始 EVE</h2><pre v-if="record.event.original" class="raw-data technical">{{record.event.original}}</pre><a-empty v-else description="当前账号未获原始载荷读取权限"/>
 </div></a-modal>
</template>
<style scoped>.traffic-detail .technical{overflow-wrap:anywhere}.traffic-detail h2{font-size:16px;margin:12px 0 8px}</style>
