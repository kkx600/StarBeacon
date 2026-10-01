<script setup lang="ts">
import { shallowRef } from 'vue'
import { session } from '../../session'
import { message, Modal as AModal, Descriptions as ADescriptions } from 'ant-design-vue'
const ADescriptionsItem = ADescriptions.Item
import type { Sensor } from '@starbeacon/shared/types.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import { formatTime, formatPercent, formatHealthErrors, taskNames } from '@starbeacon/shared/types.ts'
const props=defineProps<{sensor: Sensor | null}>()
const emit = defineEmits<{close: [];submitted:[]}>()
const pending=shallowRef(false)
let key:string|undefined
let keySensor=''
async function diagnostics(){if(!props.sensor)return;pending.value=true;if(keySensor!==props.sensor.id){key=undefined;keySensor=props.sensor.id}key??=crypto.randomUUID();try{await session.api.request(`/sensors/${encodeURIComponent(props.sensor.id)}/tasks`,{method:'POST',body:{kind:'diagnostics'},headers:{'Idempotency-Key':key}});key=undefined;message.success('运行诊断已受理，请在任务记录中查看执行回执');emit('submitted')}catch(e){message.error(e instanceof Error?e.message:'任务提交失败')}finally{pending.value=false}}
</script>
<template>
  <a-modal title="探针详情" :open="sensor !== null" :footer="null" :width="760" @cancel="emit('close')">
    <div v-if="sensor" class="detail-content">
      <a-alert type="info" show-icon message="健康数据为最后一次宿主机观测；网络接口计数不等同于镜像捕获吞吐。" class="section-gap" />
      <div v-if="session.current.value?.role==='admin'" class="filter-actions section-gap"><a-button type="primary" :loading="pending" :disabled="!sensor.active||!sensor.health.task_capabilities?.includes('diagnostics')" @click="diagnostics">运行诊断</a-button><span class="page-description">任务通过独立控制连接下发，结果以设备回执为准。</span></div>
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="名称">{{ sensor.name }}</a-descriptions-item>
        <a-descriptions-item label="探针标识"><span class="technical">{{ sensor.id }}</span></a-descriptions-item>
        <a-descriptions-item label="注册身份"><span class="technical">{{ sensor.registration_id }}</span></a-descriptions-item>
        <a-descriptions-item label="主机名">{{ sensor.health.hostname ?? '未获取' }}</a-descriptions-item>
        <a-descriptions-item label="最后观测时间">{{ formatTime(sensor.last_seen) }}</a-descriptions-item>
        <a-descriptions-item label="CPU / 内存 / 磁盘">{{ formatPercent(sensor.health.cpu_percent) }} / {{ formatPercent(sensor.health.memory_percent) }} / {{ formatPercent(sensor.health.disk_percent) }}</a-descriptions-item>
        <a-descriptions-item label="待传队列">{{ sensor.health.wal_pending ?? '未获取' }} 条</a-descriptions-item>
        <a-descriptions-item label="累计接收 / 发送"><span class="technical">{{ formatBytes(sensor.health.rx_bytes) }} / {{ formatBytes(sensor.health.tx_bytes) }}</span></a-descriptions-item>
        <a-descriptions-item label="任务能力">{{ sensor.health.task_capabilities?.map(value=>(taskNames[value]??value)).join('、')||'尚未上报' }}</a-descriptions-item>
        <a-descriptions-item label="观测异常">{{ formatHealthErrors(sensor.health.errors) }}</a-descriptions-item>
      </a-descriptions>
    </div>
  </a-modal>
</template>
