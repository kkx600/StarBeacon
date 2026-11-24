<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef } from 'vue';
import { Descriptions as ADescriptions } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import {
  formatPercent,
  formatTime,
  formatHealthErrors,
  type MetricSpec,
  type PlatformHealth,
} from '@starbeacon/shared/types.ts';
import { formatNumber, formatBytes } from '@starbeacon/shared/utils/format.ts';
import { session } from '../../session';
const ADescriptionsItem = ADescriptions.Item;
const result = shallowRef<PlatformHealth | null>(null),
  pending = shallowRef(true),
  error = shallowRef('');
const serviceNames: Record<string, string> = {
  postgresql: '平台数据库',
  redis: '缓存与登录限流',
  elasticsearch: '告警检索',
  packet_storage: '原包存储',
};
const backendNames: Record<string, string> = { filesystem: '本地或挂载文件系统', s3: 'S3 兼容对象存储' };
const unavailable = computed(
  () => result.value && Object.values(result.value.services).some(state => state !== 'ready'),
);
// 原包存储由全部租户共享：容量来自部署存储，原包数量与可回溯时间只统计当前租户。
const storage = computed(() => result.value?.packet_storage);
const amount = (value: string) => (/^\d{1,20}$/.test(value) ? BigInt(value) : null);
const count = (value: string) => {
  const parsed = amount(value);
  return parsed === null ? '未获取' : formatNumber(parsed);
};
const pressure = computed(() => {
  const value = storage.value;
  if (!value?.measured) return false;
  const free = amount(value.free_bytes),
    floor = amount(value.floor_bytes);
  return free !== null && floor !== null && free < floor;
});
const limited = computed(() => (amount(storage.value?.limit_bytes ?? '') ?? 0n) > 0n);
const reach = computed(() => {
  const oldest = storage.value?.oldest_created_at,
    observed = result.value?.observed_at;
  if (!oldest || !observed) return '';
  const days = Math.max(0, (Date.parse(observed) - Date.parse(oldest)) / 86400000);
  return Number.isFinite(days) ? `${days < 10 ? days.toFixed(1) : Math.floor(days)} 天` : '';
});
const runtimeMetrics = computed<MetricSpec[]>(() => {
  const runtime = result.value?.runtime;
  if (!runtime) return [];
  return [
    {
      label: 'CPU 使用率',
      value: formatPercent(runtime.cpu_percent),
      note: '所在运行环境观测',
      missingReason: '未获取运行环境 CPU 指标',
    },
    {
      label: '内存使用率',
      value: formatPercent(runtime.memory_percent),
      note: '所在运行环境观测',
      missingReason: '未获取运行环境内存指标',
    },
    {
      label: '磁盘使用率',
      value: formatPercent(runtime.disk_percent),
      note: '进程工作目录所在磁盘',
      missingReason: '未获取进程工作目录的磁盘指标',
    },
    {
      label: '进程堆内存',
      value: formatBytes(runtime.heap_bytes),
      note: '平台进程实际分配',
      missingReason: '未获取堆内存观测',
    },
  ];
});
const storageMetrics = computed<MetricSpec[]>(() => {
  const value = storage.value;
  if (!value) return [];
  const limit = formatBytes(value.limit_bytes, true);
  const retention = `保留期上限 ${value.retention_days} 天`;
  const occupied = `占用 ${formatBytes(value.stored_bytes, true)}`;
  return [
    {
      label: '共享剩余空间',
      value: value.measured ? formatBytes(value.free_bytes, true) : null,
      note: `总容量 ${formatBytes(value.total_bytes, true)}`,
      tone: pressure.value ? 'warning' : undefined,
      missingReason: value.measured ? '未获取部署存储的剩余空间' : '对象存储无法测量剩余空间',
    },
    value.measured
      ? {
          label: '回收阈值',
          value: formatBytes(value.floor_bytes, true),
          note: limited.value ? `剩余低于该值或总量超过 ${limit} 时回收` : '剩余低于该值时回收最早原包',
        }
      : {
          label: '目录上限',
          value: limited.value ? limit : '不限',
          note: limited.value ? '总量超过上限时回收最早原包' : '未设置上限，只按保留期删除',
        },
    {
      label: '本租户原包',
      value: count(value.archives),
      note: occupied,
      missingReason: `未获取本租户原包计数 · ${occupied}`,
    },
    {
      label: '实际可回溯',
      value: reach.value || null,
      note: `最早 ${formatTime(value.oldest_created_at)}，${retention}`,
      missingReason: `${value.oldest_created_at ? '无法核对最早归档时间' : '暂无原包'} · ${retention}`,
    },
  ];
});
let controller: AbortController | undefined;
async function refresh() {
  controller?.abort();
  const active = new AbortController();
  controller = active;
  pending.value = true;
  error.value = '';
  try {
    const value = await session.api.request<PlatformHealth>('/platform/health', { signal: active.signal });
    if (!active.signal.aborted) result.value = value;
  } catch (e) {
    if (!active.signal.aborted) error.value = e instanceof Error ? e.message : '运行状态读取失败';
  } finally {
    if (controller === active) pending.value = false;
  }
}
onMounted(refresh);
onScopeDispose(() => controller?.abort());
</script>
<template>
  <div class="filter-actions section-gap">
    <a-button :loading="pending" @click="refresh">刷新运行状态</a-button
    ><span class="page-description">{{ result ? `观测时间 ${formatTime(result.observed_at)}` : '等待平台观测' }}</span>
  </div>
  <StatePanel :loading="pending" :error="error" @retry="refresh"
    ><template v-if="result">
      <a-alert
        v-if="unavailable"
        type="warning"
        message="部分平台依赖不可用，相关操作可能无法完成，请核对服务状态。"
        show-icon
        class="section-gap"
      />
      <a-alert
        v-if="result.runtime.errors.length"
        :message="formatHealthErrors(result.runtime.errors)"
        type="warning"
        show-icon
        class="section-gap"
      />
      <MetricBar :items="runtimeMetrics" />
      <section class="panel">
        <div class="panel-header"><h2>依赖服务</h2></div>
        <div class="platform-services">
          <div v-for="(state, name) in result.services" :key="name">
            <span>{{ serviceNames[String(name)] ?? name }}</span>
            <StatusTag
              :value="state === 'ready' ? '可用' : '不可用'"
              :tone="state === 'ready' ? statusTerms.正常 : statusTerms.异常"
            />
          </div>
        </div>
      </section>
      <section v-if="storage" class="panel packet-storage" aria-labelledby="packet-storage-title">
        <div class="panel-header">
          <h2 id="packet-storage-title">原包存储</h2>
          <PageHelp title="原包存储">
            <p>原包存储由全部租户共享。可回溯范围由部署存储容量和实际流量决定。</p>
            <p>空间不足时先回收最早归档的原包，跳过正在下载或导出的原包。每个原包最多保留到其期限。</p>
          </PageHelp>
          <span class="page-description">{{ backendNames[storage.backend] ?? storage.backend }}，全部租户共享</span>
        </div>
        <MetricBar :items="storageMetrics" embedded />
        <div v-if="pressure" class="panel-body">
          <a-alert
            type="warning"
            show-icon
            class="section-gap"
            message="共享存储剩余空间低于回收阈值，平台正在按全部租户最早归档的顺序回收原包；需要更长回溯时请扩容存储。"
          />
        </div>
      </section>
      <section class="panel">
        <div class="panel-header">
          <h2>运行信息</h2>
          <PageHelp title="运行信息"
            ><p>此处展示平台运行环境与依赖观测，采集质量和队列容量需在对应工作区核对。</p></PageHelp
          >
        </div>
        <div class="panel-body">
          <a-descriptions size="small" :column="1"
            ><a-descriptions-item label="版本">{{ result.runtime.version }}</a-descriptions-item
            ><a-descriptions-item label="提交标识"
              ><span class="technical">{{ result.runtime.commit }}</span></a-descriptions-item
            ><a-descriptions-item label="运行协程">{{
              formatNumber(result.runtime.goroutines)
            }}</a-descriptions-item></a-descriptions
          >
        </div>
      </section>
    </template></StatePanel
  >
</template>
<style scoped>
.platform-services {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--section-gap);
  padding: 0 var(--panel-inset) var(--panel-inset);
}
.platform-services > div {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--related-gap);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: var(--section-gap);
  min-width: 0;
  flex-wrap: wrap;
}
.packet-storage .panel-header {
  flex-wrap: wrap;
  justify-content: flex-start;
}
</style>
