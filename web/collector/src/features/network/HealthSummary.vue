<script setup lang="ts">
import type { HostHealth } from '@starbeacon/shared/types.ts'
import { formatPercent,formatTime,formatHealthErrors } from '@starbeacon/shared/types.ts'
defineProps<{health:HostHealth}>()
</script>
<template>
  <a-alert v-if="health.errors?.length" type="warning" show-icon :message="formatHealthErrors(health.errors)" class="section-gap" />
  <section class="panel"><div class="metric-grid"><div><span>CPU 使用率</span><strong>{{ formatPercent(health.cpu_percent) }}</strong><small>宿主机观测</small></div><div><span>内存使用率</span><strong>{{ formatPercent(health.memory_percent) }}</strong><small>宿主机观测</small></div><div><span>磁盘使用率</span><strong>{{ formatPercent(health.disk_percent) }}</strong><small>本地状态目录所在磁盘</small></div><div><span>待传队列</span><strong>{{ health.wal_pending }}</strong><small>尚未取得持久接收确认</small></div></div><div class="panel-body page-description">{{ health.hostname }} · 版本 {{ health.version }} · 观测时间 {{ formatTime(health.observed_at) }}</div></section>
</template>
