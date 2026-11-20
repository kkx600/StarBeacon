<script setup lang="ts">
import {computed} from 'vue'
import {formatQuantity} from '../../../web/packages/shared/src/utils/format'
import type {MetricSpec} from '../models'

const props = defineProps<{items: MetricSpec[]}>()

// 数字默认用正文色。只有表示风险（警示、危险）且数值大于 0 时才着色；0 和无数据保持中性。
function riskTone(item: MetricSpec): 'warning' | 'danger' | undefined {
  if (item.tone !== 'warning' && item.tone !== 'danger') return undefined
  const leading = Number.parseFloat(String(item.value).replace(/,/g, ''))
  return Number.isFinite(leading) && leading > 0 ? item.tone : undefined
}

const displayed = computed(() =>
  props.items.map(item => {
    const tone = riskTone(item)
    if (!item.suffix || !/(?:B|bit\/s)$/.test(item.suffix)) return {...item, tone}
    const formatted = formatQuantity(`${item.value} ${item.suffix}`)
    const space = formatted.lastIndexOf(' ')
    return {...item, tone, value: formatted.slice(0, space), suffix: formatted.slice(space + 1)}
  }),
)
</script>

<template>
  <div class="metric-bar">
    <div v-for="item in displayed" :key="item.label" class="metric-item">
      <span>{{ item.label }}</span>
      <strong :class="item.tone">{{ item.value }}<small v-if="item.suffix">{{ item.suffix }}</small></strong>
      <small v-if="item.note" class="metric-note">{{ item.note }}</small>
    </div>
  </div>
</template>
