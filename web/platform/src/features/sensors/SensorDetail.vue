<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import { computed,onScopeDispose,shallowRef,watch } from 'vue'
import { session } from '../../session'
import { Modal as AModal, Descriptions as ADescriptions} from 'ant-design-vue'
const ADescriptionsItem = ADescriptions.Item
import type { Sensor } from '@starbeacon/shared/types.ts'
import ProtocolCapabilitiesDialog from '@starbeacon/shared/components/ProtocolCapabilitiesDialog.vue'
import DetectionQualityDialog from '@starbeacon/shared/components/DetectionQualityDialog.vue'
import EngineHealthSummary from '@starbeacon/shared/components/EngineHealthSummary.vue'
import {basicApplicationState} from '@starbeacon/shared/application.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import {packetStates} from '@starbeacon/shared/packetArchives.ts'
import { captureStates,formatTime, formatPercent, formatHealthErrors, taskNames } from '@starbeacon/shared/types.ts'
const message=useFeedback()
const props=defineProps<{sensor: Sensor | null}>()
const emit = defineEmits<{close: [];submitted:[];configure:[sensor:Sensor];respond:[sensor:Sensor];certificates:[sensor:Sensor]}>()
const pending=shallowRef(false)
const protocolsOpen=shallowRef(false)
const qualityOpen=shallowRef(false)
const applicationState=computed(()=>basicApplicationState(props.sensor?.health.application_rules)?props.sensor!.health.application_rules:null)
const capture=computed(()=>props.sensor?.health.capture)
const captureStatus=computed(()=>capture.value?.status ? captureStates[capture.value.status]??'状态无法识别' : props.sensor?.health.capture_status==='eve_reader_only'?'外部 EVE 文件':'尚未观测')
let key:string|undefined
let keySensor=''
let controller:AbortController|undefined,stopped=false
async function diagnostics() {
  if(!props.sensor||pending.value||stopped||session.current.value?.role!=='admin')return
  pending.value=true
  if(keySensor!==props.sensor.id){key=undefined;keySensor=props.sensor.id}
  key??=crypto.randomUUID()
  const current=new AbortController();controller=current
  try {
    await session.api.request(`/sensors/${encodeURIComponent(props.sensor.id)}/tasks`,{method:'POST',body:{kind:'diagnostics'},headers:{'Idempotency-Key':key},signal:current.signal})
    if(current.signal.aborted)return
    key=undefined;message.success('运行诊断已受理，请在任务记录中查看执行回执');emit('submitted')
  } catch(e){if(!current.signal.aborted)message.error(e instanceof Error?e.message:'任务提交失败')}
  finally{if(!current.signal.aborted)pending.value=false}
}
watch(()=>`${props.sensor?.id??''}/${props.sensor?.registration_id??''}`,()=>{controller?.abort();pending.value=false;protocolsOpen.value=false;qualityOpen.value=false;key=undefined;keySensor=''})
onScopeDispose(()=>{stopped=true;controller?.abort()})
</script>
<template>
  <a-modal title="探针详情" :open="sensor !== null" :footer="null" :width="760" :closable="!pending" :mask-closable="!pending" :keyboard="!pending" @cancel="emit('close')">
    <div v-if="sensor" class="detail-content">
      <a-alert type="info" show-icon message="健康数据为最后一次宿主机观测；网络接口计数不等同于镜像捕获吞吐。" class="section-gap" />
      <a-alert v-if="sensor.status !== 'online'" type="warning" show-icon message="探针当前未在线，以下健康信息为历史观测，不能确认设备当前状态。" class="section-gap" />
      <div class="filter-actions section-gap"><a-button @click="protocolsOpen=true">协议能力</a-button><a-button @click="qualityOpen=true">检测质量</a-button><a-button v-if="session.current.value?.role==='admin'" @click="emit('certificates',sensor)">注册与证书</a-button><span class="page-description">按本探针最后观测的引擎与配置核对能力及限制。</span></div>
      <div v-if="session.current.value?.role==='admin'" class="filter-actions section-gap"><a-button type="primary" :loading="pending" :disabled="!sensor.active||!sensor.health.task_capabilities?.includes('diagnostics')" @click="diagnostics">运行诊断</a-button><a-button v-if="sensor.health.capture?.managed" :disabled="pending||!sensor.active||sensor.status!=='online'||!sensor.health.task_capabilities?.includes('capture.configure')" @click="emit('configure',sensor)">采集配置</a-button><a-button v-if="sensor.health.task_capabilities?.includes('response.block')" :disabled="pending||!sensor.active||sensor.status!=='online'" @click="emit('respond',sensor)">限时封禁</a-button><span class="page-description">任务通过独立控制连接下发，结果以设备回执为准。</span></div>
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="名称">{{ sensor.name }}</a-descriptions-item>
        <a-descriptions-item label="探针分组">{{sensor.group_name||(sensor.group_id?'分组名称待核查':'未分组')}}</a-descriptions-item>
        <a-descriptions-item label="部署站点">{{sensor.site||'未填写'}}</a-descriptions-item>
        <a-descriptions-item label="说明">{{sensor.description||'未填写'}}</a-descriptions-item>
        <a-descriptions-item label="管理信息修订">{{sensor.metadata_revision??'未获取'}} · {{formatTime(sensor.metadata_updated_at)}}</a-descriptions-item>
        <a-descriptions-item label="探针标识"><span class="technical">{{ sensor.id }}</span></a-descriptions-item>
        <a-descriptions-item label="注册身份"><span class="technical">{{ sensor.registration_id }}</span></a-descriptions-item>
        <a-descriptions-item label="主机名">{{ sensor.health.hostname ?? '未获取' }}</a-descriptions-item>
        <a-descriptions-item label="最后观测时间">{{ formatTime(sensor.last_seen) }}</a-descriptions-item>
        <a-descriptions-item label="CPU / 内存 / 磁盘">{{ formatPercent(sensor.health.cpu_percent) }} / {{ formatPercent(sensor.health.memory_percent) }} / {{ formatPercent(sensor.health.disk_percent) }}</a-descriptions-item>
        <a-descriptions-item label="待传队列">{{ sensor.health.wal_pending ?? '未获取' }} 条</a-descriptions-item>
        <a-descriptions-item label="累计接收 / 发送"><span class="technical">{{ formatBytes(sensor.health.rx_bytes) }} / {{ formatBytes(sensor.health.tx_bytes) }}</span></a-descriptions-item>
        <a-descriptions-item label="检测状态">{{ captureStatus }}</a-descriptions-item>
        <template v-if="sensor.health.packet_archive"><a-descriptions-item label="原包捕获">{{packetStates[sensor.health.packet_archive.state]??'状态待核查'}} · 观测 {{formatTime(sensor.health.packet_archive.observed_at)}}</a-descriptions-item><a-descriptions-item label="原包暂存额度">{{formatBytes(sensor.health.packet_archive.reserved_bytes)}} / {{formatBytes(sensor.health.packet_archive.quota_bytes)}}</a-descriptions-item><a-descriptions-item label="最近归档确认">{{formatTime(sensor.health.packet_archive.last_confirmed_at)}}</a-descriptions-item></template>
        <a-descriptions-item v-if="sensor.health.network_interfaces" label="本机网卡"><div v-for="nic in sensor.health.network_interfaces" :key="nic.name"><span class="technical">{{nic.name}}</span> · {{nic.up?'启用':'关闭'}}{{nic.loopback?' · 回环':''}} · <span class="capture-digest">{{nic.mac||'未提供 MAC'}}{{nic.addresses.length?' · '+nic.addresses.join('、'):''}}</span></div></a-descriptions-item>
        <template v-if="capture?.managed">
          <a-descriptions-item label="生效采集网卡">{{ capture.applied_settings?.interfaces.join('、') || '未采集' }}</a-descriptions-item>
          <a-descriptions-item label="采集配置修订">期望 {{ capture.revision ?? '未获取' }} / 生效 {{ capture.applied_revision ?? '未获取' }}</a-descriptions-item>
          <a-descriptions-item label="检测观测时间">{{ formatTime(capture.observed_at) }}</a-descriptions-item>
          <a-descriptions-item label="引擎累计流量">{{ formatBytes(capture.counters?.['decoder.bytes']) }}</a-descriptions-item>
          <a-descriptions-item label="捕获计数时间">{{ formatTime(capture.counters_observed_at) }}</a-descriptions-item>
          <a-descriptions-item label="EVE 缓冲占用">{{ formatBytes(capture.spool_bytes) }} / {{ formatBytes(capture.spool_budget) }}</a-descriptions-item>
          <a-descriptions-item v-if="capture.rotation_pending" label="来源轮转">旧来源等待持久排空，缓冲文件继续保留</a-descriptions-item>
        </template>
        <a-descriptions-item label="应用识别规则">{{applicationState?applicationState.rule_count+' 条 / '+(applicationState.deployment_id||'尚未部署'):'未提供可核对的状态'}}</a-descriptions-item>
        <a-descriptions-item v-if="applicationState" label="应用规则快照"><span class="capture-digest">{{applicationState.rules_sha256}}</span> · {{formatTime(applicationState.installed_at)}}</a-descriptions-item>
        <a-descriptions-item label="登记规则文件摘要"><span class="capture-digest">{{ sensor.health.registered_rules_sha256 || '尚未观测' }}</span></a-descriptions-item>
        <a-descriptions-item label="任务能力">{{ sensor.health.task_capabilities?.map(value=>(taskNames[value]??value)).join('、')||'尚未上报' }}</a-descriptions-item>
        <a-descriptions-item label="观测异常">{{ formatHealthErrors(sensor.health.errors) }}</a-descriptions-item>
      </a-descriptions>
      <EngineHealthSummary :report="sensor.health.engine_health" />
    </div>
  </a-modal>
  <ProtocolCapabilitiesDialog :open="protocolsOpen&&sensor!==null" :name="sensor?.name" :report="sensor?.health.protocol_capabilities" :capture="capture" @close="protocolsOpen=false" />
  <DetectionQualityDialog :open="qualityOpen&&sensor!==null" :capture="capture" :online="sensor?.status==='online'" @close="qualityOpen=false" />
</template>
<style scoped>
.capture-digest{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
</style>
