<script setup lang="ts">
import {computed} from 'vue'
import {Descriptions as ADescriptions} from 'ant-design-vue'
import type {ResponseAction} from '../response'
import {validResponseProtection,type ResponseProtection} from '../responseProtection'
import {formatTime} from '../types'

const ADescriptionsItem=ADescriptions.Item

const props=defineProps<{action:ResponseAction;proof?:ResponseProtection}>()
const valid=computed(()=>props.proof&&validResponseProtection(props.proof,'response.block',props.action.requested_at,props.action.expires_at))
</script>
<template>
  <section class="section-gap" aria-label="封禁授权的名单核对">
    <a-alert v-if="proof&&!valid" type="error" show-icon message="名单核对记录不完整，请刷新任务详情核对。"/>
    <a-alert v-else-if="!proof" type="info" show-icon message="该历史任务没有名单核对记录，不能据此认定当时已核对保护名单。"/>
    <template v-else>
      <a-alert type="info" show-icon message="平台授权时未命中有效保护名单" description="记录绑定原任务与当时名单状态。后续名单变更不自动撤销已有签名任务或租约，也不表示设备执行时再次核对名单。"/>
      <a-descriptions bordered :column="1" size="small" class="protection-details">
        <a-descriptions-item label="名单核对时间">{{formatTime(proof.check.checked_at)}}</a-descriptions-item>
        <a-descriptions-item label="名单状态 SHA-256"><span class="technical">{{proof.check.state_sha256}}</span></a-descriptions-item>
        <a-descriptions-item label="原命令 SHA-256"><span class="technical">{{proof.command_sha256}}</span></a-descriptions-item>
        <a-descriptions-item label="核对记录 SHA-256"><span class="technical">{{proof.check_sha256}}</span></a-descriptions-item>
      </a-descriptions>
    </template>
  </section>
</template>
<style scoped>
.protection-details{margin-top:var(--related-gap)}.technical{overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
</style>
