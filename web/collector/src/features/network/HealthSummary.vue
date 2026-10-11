<script setup lang="ts">
import type { HostHealth } from '@starbeacon/shared/types.ts'
import { formatPercent,formatTime,formatHealthErrors } from '@starbeacon/shared/types.ts'
import {packetStates} from '@starbeacon/shared/packetArchives.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
defineProps<{health:HostHealth}>()
</script>
<template>
  <a-alert v-if="health.errors?.length" type="warning" show-icon :message="formatHealthErrors(health.errors)" class="section-gap" />
  <section class="panel"><div class="metric-grid"><div><span>CPU 使用率</span><strong>{{ formatPercent(health.cpu_percent) }}</strong><small>宿主机观测</small></div><div><span>内存使用率</span><strong>{{ formatPercent(health.memory_percent) }}</strong><small>宿主机观测</small></div><div><span>磁盘使用率</span><strong>{{ formatPercent(health.disk_percent) }}</strong><small>本地状态目录所在磁盘</small></div><div><span>待传队列</span><strong>{{ health.wal_pending }}</strong><small>尚未取得持久接收确认</small></div></div><div class="panel-body page-description">{{ health.hostname }} · 版本 {{ health.version }} · 观测时间 {{ formatTime(health.observed_at) }}<p v-if="health.packet_archive">原包 {{packetStates[health.packet_archive.state]??'状态待核查'}} · 暂存 {{formatBytes(health.packet_archive.reserved_bytes)}} / {{formatBytes(health.packet_archive.quota_bytes)}} · 最近平台确认 {{formatTime(health.packet_archive.last_confirmed_at)}}</p></div></section>
</template>
