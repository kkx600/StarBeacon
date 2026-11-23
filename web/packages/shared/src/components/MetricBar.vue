<script setup lang="ts">
import { computed } from 'vue';
import type { MetricSpec } from '../types';
import { formatQuantity } from '../utils/format';

const props = defineProps<{ items: readonly MetricSpec[]; embedded?: boolean; dark?: boolean }>();

const displayed = computed(() =>
  props.items.map(item => {
    const value = String(item.value ?? '').trim();
    const missing =
      ['', '—', '无数据', '未获取', '未提供'].includes(value) ||
      (typeof item.value === 'number' && !Number.isFinite(item.value));
    if (missing) {
      return { label: item.label, value: '—', note: item.missingReason || '未取得观测值', missing };
    }

    const count = Number.parseFloat(value.replaceAll(',', ''));
    const risk = item.tone === 'warning' || item.tone === 'danger';
    const tone = risk && Number.isFinite(count) && count > 0 ? item.tone : undefined;
    const normalized =
      item.suffix && /(?:B|bit\/s)$/.test(item.suffix) ? formatQuantity(`${value} ${item.suffix}`) : '';
    const separator = normalized.lastIndexOf(' ');
    return {
      label: item.label,
      value: separator < 0 ? value : normalized.slice(0, separator),
      suffix: separator < 0 ? item.suffix : normalized.slice(separator + 1),
      note: item.note,
      tone,
      missing,
    };
  }),
);
</script>

<template>
  <div class="metric-bar" :data-embedded="embedded || undefined" :data-dark="dark || undefined">
    <div v-for="item in displayed" :key="item.label" class="metric-item" :data-missing="item.missing || undefined">
      <span class="metric-label">{{ item.label }}</span>
      <strong class="metric-value" :data-tone="item.tone" :aria-label="item.missing ? '无数据' : undefined"
        >{{ item.value }}<small v-if="item.suffix" class="metric-suffix">{{ item.suffix }}</small></strong
      >
      <small v-if="item.note" class="metric-note">{{ item.note }}</small>
    </div>
  </div>
</template>

<style scoped>
.metric-bar {
  display: flex;
  min-width: 0;
  padding: var(--related-gap) 0;
  margin-bottom: var(--related-gap);
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
}
.metric-bar[data-embedded] {
  margin-bottom: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
}
.metric-item {
  display: flex;
  flex: 1;
  min-width: 0;
  flex-wrap: wrap;
  align-content: start;
  align-items: baseline;
  gap: 2px 10px;
  padding: 0 var(--panel-inset);
  border-right: 1px solid var(--line);
}
.metric-item:last-child {
  border-right: 0;
}
.metric-label,
.metric-note,
.metric-suffix {
  color: var(--muted);
  font-size: 12px;
  font-weight: 400;
  overflow-wrap: anywhere;
}
.metric-value {
  min-width: 0;
  color: var(--text);
  font-size: 20px;
  font-weight: 600;
  line-height: 28px;
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}
.metric-suffix {
  margin-inline-start: 5px;
}
.metric-value[data-tone='warning'] {
  color: var(--warning);
}
.metric-value[data-tone='danger'] {
  color: var(--danger);
}
.metric-bar[data-dark] {
  margin-bottom: var(--section-gap);
  padding: var(--panel-inset) 0;
  border-color: var(--screen-line);
  background: var(--screen-metric);
}
.metric-bar[data-dark] .metric-item {
  flex-direction: column;
  flex-wrap: nowrap;
  align-items: stretch;
  gap: var(--label-gap);
  border-right-color: var(--screen-line);
}
.metric-bar[data-dark] .metric-value {
  color: var(--screen-number);
  font-size: 24px;
  line-height: 1.25;
}
.metric-bar[data-dark] .metric-value[data-tone='warning'] {
  color: var(--screen-amber);
}
.metric-bar[data-dark] .metric-value[data-tone='danger'] {
  color: var(--screen-danger);
}
.metric-bar[data-dark] .metric-label,
.metric-bar[data-dark] .metric-note,
.metric-bar[data-dark] .metric-suffix {
  color: var(--screen-muted);
}
</style>
