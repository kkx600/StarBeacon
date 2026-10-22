<script setup lang="ts">
import { Modal as AModal } from 'ant-design-vue'
import {computed} from 'vue'
import type { CaptureConfig } from '../types'
import {isProtocolReport} from '../protocols'
import ProtocolCapabilities from './ProtocolCapabilities.vue'
const props=defineProps<{open:boolean; report?:unknown; capture?:CaptureConfig; name?:string;refreshable?:boolean;loading?:boolean;error?:string}>()
const hasObservation=computed(()=>isProtocolReport(props.report))
const emit = defineEmits<{close:[];refresh:[]}>()
</script>
<template>
  <a-modal :title="name?`协议能力 · ${name}`:'协议能力'" :open="open" :footer="null" :width="1120" destroy-on-close @cancel="emit('close')">
    <div v-if="refreshable" class="filter-actions section-gap"><a-button :loading="loading" @click="emit('refresh')">刷新观测</a-button></div>
    <a-alert v-if="error" type="warning" show-icon class="section-gap" :message="hasObservation?'刷新失败，保留上次观测':'协议能力读取失败'" :description="hasObservation?`${error}。当前保留上次观测及其采样时间，请重试刷新观测。`:`${error}。尚未取得本次观测，不能据此判断采集器是否上报协议能力。请重试刷新观测。`" />
    <div v-if="loading&&!hasObservation" role="status" class="page-description"><a-spin size="small" /> 正在读取协议能力观测…</div>
    <ProtocolCapabilities v-else-if="!error||hasObservation" :report="report" :capture="capture" />
  </a-modal>
</template>
