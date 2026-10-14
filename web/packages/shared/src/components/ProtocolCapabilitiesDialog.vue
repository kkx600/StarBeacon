<script setup lang="ts">
import { Modal as AModal } from 'ant-design-vue'
import type { CaptureConfig } from '../types'
import ProtocolCapabilities from './ProtocolCapabilities.vue'
defineProps<{open:boolean; report?:unknown; capture?:CaptureConfig; name?:string;refreshable?:boolean;loading?:boolean}>()
const emit = defineEmits<{close:[];refresh:[]}>()
</script>
<template><a-modal :title="name?`协议能力 · ${name}`:'协议能力'" :open="open" :footer="null" :width="1120" destroy-on-close @cancel="emit('close')"><div v-if="refreshable" class="filter-actions section-gap"><a-button :loading="loading" @click="emit('refresh')">刷新观测</a-button></div><ProtocolCapabilities :report="report" :capture="capture" /></a-modal></template>
