<script setup lang="ts">
import { Modal as AModal, Descriptions as ADescriptions } from 'ant-design-vue'
const ADescriptionsItem = ADescriptions.Item
import type { Alert } from '@starbeacon/shared/types.ts'
import { formatTime } from '@starbeacon/shared/types.ts'
defineProps<{alert: Alert | null}>()
const emit = defineEmits<{close: []}>()
</script>
<template>
  <a-modal title="告警详情" :open="alert !== null" :width="880" :footer="null" @cancel="emit('close')">
    <div v-if="alert" class="detail-content">
      <a-alert type="info" show-icon message="规则命中不代表攻击成功。当前记录未关联原生会话证据。" class="section-gap" />
      <a-descriptions bordered :column="1" size="small">
        <a-descriptions-item label="告警名称">{{ alert.rule.name }}</a-descriptions-item>
        <a-descriptions-item label="事件标识"><span class="technical">{{ alert.event_id }}</span></a-descriptions-item>
        <a-descriptions-item label="源 IP / MAC">{{ alert.source.ip ?? '未提供' }} / {{ alert.source.mac ?? '未观测到' }}</a-descriptions-item>
        <a-descriptions-item label="目的 IP / MAC">{{ alert.destination.ip ?? '未提供' }} / {{ alert.destination.mac ?? '未观测到' }}</a-descriptions-item>
        <a-descriptions-item label="传输 / 应用协议">{{ alert.network.transport ?? '未提供' }} / {{ alert.network.protocol ?? '未提供' }}</a-descriptions-item>
        <a-descriptions-item label="请求方法 / 路径">{{ alert.http.method ?? '未提供' }} / {{ alert.http.path ?? '未提供' }}</a-descriptions-item>
        <a-descriptions-item label="流标识"><span class="technical">{{ alert.suricata.flow_id ?? '未提供' }}</span></a-descriptions-item>
        <a-descriptions-item label="事件发生时间">{{ formatTime(alert['@timestamp']) }}</a-descriptions-item>
        <a-descriptions-item label="代理观察时间">{{ formatTime(alert.observed_at) }}</a-descriptions-item>
        <a-descriptions-item label="平台接收时间">{{ formatTime(alert.received_at) }}</a-descriptions-item>
        <a-descriptions-item label="原始摘要"><span class="technical">{{ alert.raw_sha256 }}</span></a-descriptions-item>
      </a-descriptions>
      <h2>原始 EVE</h2><pre v-if="alert.event.original" class="raw-data technical">{{ alert.event.original }}</pre><a-empty v-else description="当前账号未获原始载荷读取权限" />
    </div>
  </a-modal>
</template>
