<script setup lang="ts">
import type { StatusTone } from '../terms';

defineProps<{ value: unknown; tone: StatusTone; dark?: boolean }>();
</script>

<template>
  <span class="status-tag" :data-tone="tone" :data-dark="dark || undefined">
    <span class="status-tag-dot" aria-hidden="true"></span>{{ value == null ? '无数据' : String(value) }}
  </span>
</template>

<style scoped>
.status-tag {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 1px 7px;
  border-radius: 4px;
  white-space: nowrap;
  background: var(--tag-surface, var(--status-surface));
  color: var(--tag-text, var(--status-text));
  font-size: 12px;
  line-height: 18px;
}
.status-tag-dot {
  flex: none;
  width: 6px;
  height: 6px;
  border-radius: 4px;
  background: var(--tag-dot, currentColor);
}
.status-tag[data-tone='success'] {
  --tag-surface: var(--success-surface);
  --tag-text: var(--success);
  --tag-dot: var(--success-dot);
}
.status-tag[data-tone='warning'] {
  --tag-surface: var(--warning-surface);
  --tag-text: var(--warning);
  --tag-dot: var(--warning-dot);
}
.status-tag[data-tone='danger'] {
  --tag-surface: var(--danger-surface);
  --tag-text: var(--danger);
  --tag-dot: var(--danger-dot);
}
.status-tag[data-tone='info'] {
  --tag-surface: var(--progress-surface);
  --tag-text: var(--progress-text);
}
.status-tag[data-tone='critical'] {
  --tag-surface: var(--critical);
  --tag-text: var(--critical-text);
}
.status-tag[data-dark] {
  --tag-text: var(--screen-muted);
  --tag-dot: currentColor;
  --tag-surface: color-mix(in srgb, currentColor 16%, transparent);
}
.status-tag[data-dark][data-tone='success'] {
  --tag-text: var(--screen-teal);
}
.status-tag[data-dark][data-tone='warning'] {
  --tag-text: var(--screen-amber);
}
.status-tag[data-dark][data-tone='danger'] {
  --tag-text: var(--screen-danger);
}
.status-tag[data-dark][data-tone='info'] {
  --tag-text: var(--screen-blue);
}
.status-tag[data-dark][data-tone='critical'] {
  --tag-surface: var(--critical);
  --tag-text: var(--critical-text);
}
</style>
