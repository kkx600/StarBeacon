<script setup lang="ts">
import {Modal as AModal} from 'ant-design-vue'
import type {CaptureConfig} from '../types'
import DetectionQuality from './DetectionQuality.vue'
defineProps<{open:boolean; capture?:CaptureConfig; online?:boolean; refreshable?:boolean; loading?:boolean; error?:string}>()
const emit=defineEmits<{close:[]; refresh:[]}>()
</script>
<template><a-modal title="检测质量" :open="open" :width="860" @cancel="emit('close')"><a-alert v-if="error" type="warning" show-icon message="刷新失败，保留上次观测" :description="`${error}。请重试刷新观测；累计值、采样时间和区间均未更新。`" class="section-gap"/><DetectionQuality v-if="open" :capture="capture" :online="online" /><template #footer><a-button v-if="refreshable" :loading="loading" @click="emit('refresh')">刷新观测</a-button><a-button @click="emit('close')">关闭</a-button></template></a-modal></template>
