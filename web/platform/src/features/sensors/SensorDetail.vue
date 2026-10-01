<script setup lang="ts">
import { Modal as AModal, Descriptions as ADescriptions } from 'ant-design-vue'
const ADescriptionsItem = ADescriptions.Item
import type { Sensor } from '@starbeacon/shared/types.ts'
import { formatTime, formatPercent, formatHealthErrors } from '@starbeacon/shared/types.ts'
defineProps<{sensor: Sensor | null}>()
const emit = defineEmits<{close: []}>()
</script>
<template>
  <a-modal title="探针详情" :open="sensor !== null" :footer="null" :width="760" @cancel="emit('close')">
    <div v-if="sensor" class="detail-content">
      <a-alert type="info" show-icon message="健康数据为最后一次宿主机观测；网络接口计数不等同于镜像捕获吞吐。" class="section-gap" />
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="名称">{{ sensor.name }}</a-descriptions-item>
        <a-descriptions-item label="探针标识"><span class="technical">{{ sensor.id }}</span></a-descriptions-item>
        <a-descriptions-item label="注册身份"><span class="technical">{{ sensor.registration_id }}</span></a-descriptions-item>
        <a-descriptions-item label="主机名">{{ sensor.health.hostname ?? '未获取' }}</a-descriptions-item>
        <a-descriptions-item label="最后观测时间">{{ formatTime(sensor.last_seen) }}</a-descriptions-item>
        <a-descriptions-item label="CPU / 内存 / 磁盘">{{ formatPercent(sensor.health.cpu_percent) }} / {{ formatPercent(sensor.health.memory_percent) }} / {{ formatPercent(sensor.health.disk_percent) }}</a-descriptions-item>
        <a-descriptions-item label="待传队列">{{ sensor.health.wal_pending ?? '未获取' }} 条</a-descriptions-item>
        <a-descriptions-item label="累计收 / 发字节"><span class="technical">{{ sensor.health.rx_bytes ?? '未获取' }} / {{ sensor.health.tx_bytes ?? '未获取' }}</span></a-descriptions-item>
        <a-descriptions-item label="观测异常">{{ formatHealthErrors(sensor.health.errors) }}</a-descriptions-item>
      </a-descriptions>
    </div>
  </a-modal>
</template>
