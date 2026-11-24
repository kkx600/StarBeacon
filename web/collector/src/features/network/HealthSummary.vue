<script setup lang="ts">
import { computed } from 'vue';
import type { HostHealth, MetricSpec } from '@starbeacon/shared/types.ts';
import { formatPercent, formatTime, formatHealthErrors } from '@starbeacon/shared/types.ts';
import { packetStates, retentionDegradations } from '@starbeacon/shared/packetArchives.ts';
import { formatBytes } from '@starbeacon/shared/utils/format.ts';
import EngineHealthSummary from '@starbeacon/shared/components/EngineHealthSummary.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';

const props = defineProps<{ health: HostHealth }>();
const metrics = computed<MetricSpec[]>(() => {
  const health = props.health;
  return [
    {
      label: 'CPU 使用率',
      value: formatPercent(health.cpu_percent),
      note: '宿主机观测',
      missingReason: '宿主机 CPU 指标无数据',
    },
    {
      label: '内存使用率',
      value: formatPercent(health.memory_percent),
      note: '宿主机观测',
      missingReason: '宿主机内存指标无数据',
    },
    {
      label: '磁盘使用率',
      value: formatPercent(health.disk_percent),
      note: '本地状态目录所在磁盘',
      missingReason: '本地状态目录的磁盘指标无数据',
    },
    {
      label: '待传队列',
      value: health.errors?.includes('wal_unavailable') ? null : health.wal_pending,
      note: '尚未取得持久接收确认',
      missingReason: '本机待传队列统计无数据',
    },
  ];
});
</script>
<template>
  <a-alert
    v-if="health.errors?.length"
    type="warning"
    show-icon
    :message="formatHealthErrors(health.errors)"
    class="section-gap"
  />
  <section class="panel">
    <MetricBar :items="metrics" embedded />
    <div class="panel-body page-description">
      {{ health.hostname }} · 版本 {{ health.version }} · 观测时间 {{ formatTime(health.observed_at) }}
      <p v-if="health.packet_archive">
        原包 {{ packetStates[health.packet_archive.state] ?? '状态待核查' }} · 暂存
        {{ formatBytes(health.packet_archive.reserved_bytes) }} / {{ formatBytes(health.packet_archive.quota_bytes) }} ·
        最近平台确认 {{ formatTime(health.packet_archive.last_confirmed_at) }}
      </p>
      <p v-if="health.packet_archive?.last_seal?.degradation">
        {{ retentionDegradations[health.packet_archive.last_seal.degradation] }}
      </p>
    </div>
  </section>
  <EngineHealthSummary :report="health.engine_health" />
</template>
