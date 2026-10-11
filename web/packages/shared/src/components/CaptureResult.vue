<script setup lang="ts">
import {computed} from 'vue'
import {Descriptions as ADescriptions} from 'ant-design-vue'
import {captureStates,formatTime} from '../types'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{result:Record<string,unknown>}>()
const state=computed(()=>typeof props.result.status==='string'?captureStates[props.result.status as keyof typeof captureStates]??'状态无法识别':'尚未观测')
const names=(value:unknown)=>Array.isArray(value)&&value.every(i=>typeof i==='string')?(value.join('、')||'未采集'):'尚未观测'
const applied=computed(()=>props.result.applied_settings&&typeof props.result.applied_settings==='object'?(props.result.applied_settings as Record<string,unknown>).interfaces:undefined)
const revision=(value:unknown)=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0?value:'尚未观测'
const digest=computed(()=>typeof props.result.config_sha256==='string'&&/^[a-f0-9]{64}$/.test(props.result.config_sha256)?props.result.config_sha256:'尚未观测')
</script>
<template>
  <a-descriptions bordered :column="1" size="small" class="section-gap">
    <a-descriptions-item label="执行时采集状态">{{state}}</a-descriptions-item>
    <a-descriptions-item label="期望 / 生效修订">{{revision(result.revision)}} / {{revision(result.applied_revision)}}</a-descriptions-item>
    <a-descriptions-item label="期望网卡">{{names(result.interfaces)}}</a-descriptions-item>
    <a-descriptions-item label="生效网卡">{{names(applied)}}</a-descriptions-item>
    <a-descriptions-item label="回执观测时间">{{formatTime(typeof result.observed_at==='string'?result.observed_at:undefined)}}</a-descriptions-item>
    <a-descriptions-item label="检测配置摘要"><span class="technical capture-result-digest">{{digest}}</span></a-descriptions-item>
  </a-descriptions>
  <p class="page-description section-gap">此处为任务执行时的设备回执。当前采集状态请在采集配置中核对。</p>
</template>
<style scoped>.capture-result-digest{overflow-wrap:anywhere}</style>
