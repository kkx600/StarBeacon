<script setup lang="ts">
import { computed } from 'vue'
import { Modal as AModal } from 'ant-design-vue'
import type { PreviewState } from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
import ProtocolCapabilities from '../../../web/packages/shared/src/components/ProtocolCapabilities.vue'
import ProtocolCapabilityDetails from '../../../web/packages/shared/src/components/ProtocolCapabilityDetails.vue'
import ProtocolCapabilitiesDialog from '../../../web/packages/shared/src/components/ProtocolCapabilitiesDialog.vue'
import { protocolObservation } from '../data/protocols'
const props=defineProps<{state:PreviewState}>()
const emit=defineEmits<{state:[value:PreviewState]}>()
const example=protocolObservation()
const report=computed(()=>props.state==='empty'?undefined:props.state==='error'?{schema_version:1,state:'unavailable',source:'unavailable',capture_active:false,observed_at:example.observed_at,error_code:'native_protocol_inventory_unavailable',protocols:[],limits:[]}:example)
</script>
<template>
  <PageHeader title="协议能力" description="按探针、检测引擎和配置摘要，核对六层协议能力及显式检测限额。"><a-button @click="emit('state','action')">查看协议能力</a-button></PageHeader>
  <a-alert class="page-notice" type="info" show-icon message="本页面为合成示例，不调用采集器或原生引擎，不代表真实协议效果验收。" />
  <section class="panel protocol-preview-card"><div class="protocol-preview-heading"><h2>协议能力目录</h2><span class="muted">总部核心探针 · 总部站点</span></div><div><StatePanel v-if="state==='loading'" state="loading"/><ProtocolCapabilities v-else :report="report" /></div></section>
  <ProtocolCapabilitiesDialog :open="state==='action'" name="总部核心探针" :report="example" @close="emit('state','data')" />
  <a-modal title="协议能力详情" :open="state==='detail'" :width="680" :footer="null" @cancel="emit('state','data')"><ProtocolCapabilityDetails :entry="example.protocols.find(item=>item.protocol==='imap')!" /></a-modal>
</template>
<style scoped>.protocol-preview-card{padding:16px}.protocol-preview-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}.protocol-preview-heading h2{margin:0;font-size:15px;font-weight:600}</style>
