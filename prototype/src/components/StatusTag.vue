<script setup lang="ts">
import {computed} from 'vue'
import {toneOf} from '../../../web/packages/shared/src/terms'

type Tone = 'critical' | 'danger' | 'warning' | 'success' | 'info' | 'neutral'

// 调用方可以直接给出色调；没有给出时按原型示例文案归类。
// 工程端的共享状态标签只接受显式色调（见 docs/开发任务.md T07），这里的归类表只服务合成示例。
const props = defineProps<{value: unknown; tone?: Tone}>()
const text = computed(() => String(props.value ?? '无数据'))

const rules: [Tone, RegExp][] = [
  ['critical', /严重/],
  ['danger', /高危|拒绝|失败|恶意|缺少|字节缺口|异常/],
  ['warning', /未知|不足|未配置|待|占用高|丢包率高|指标不全|不完整|关注|中危|可疑|仅元数据|条件|单向|部分/],
  ['success', /成功|完成|正常|在线|已验证|生效|已送达|已发送|支持|完整|启用|已确认/],
  ['info', /运行中|研判中|处理中|重试中|灰度中/],
]
// 标准用语（web/packages/shared/src/terms.ts）优先；其余按上表归类。
const tone = computed<Tone>(() => props.tone ?? toneOf(text.value) ?? rules.find(([, pattern]) => pattern.test(text.value))?.[0] ?? 'neutral')
</script>

<template>
  <span class="status-tag" :class="tone"><span class="status-dot" :class="tone"></span>{{ text }}</span>
</template>
