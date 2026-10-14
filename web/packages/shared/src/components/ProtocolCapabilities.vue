<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue'
import { Descriptions as ADescriptions, Modal as AModal, Table as ATable } from 'ant-design-vue'
import type { CaptureConfig } from '../types'
import ProtocolCapabilityDetails from './ProtocolCapabilityDetails.vue'
import { formatTime } from '../types'
import type { ProtocolStatus } from '../protocols'
import { isProtocolReport, protocolErrors, protocolLimitNames, protocolStatus } from '../protocols'
const ADescriptionsItem = ADescriptions.Item
const props = defineProps<{report?: unknown; capture?: CaptureConfig}>()
const query = shallowRef(''), selected = shallowRef(''), sourceOpen = shallowRef(false)
const report = computed(() => isProtocolReport(props.report) ? props.report : null)
const rows = computed(() => {
  const term = query.value.trim().toLowerCase()
  return report.value?.protocols.filter(row => `${row.protocol} ${row.name}`.toLowerCase().includes(term)) ?? []
})
const detail = computed(() => report.value?.protocols.find(row => row.protocol === selected.value))
const changed = computed(() => report.value?.source === 'managed_configuration' && props.capture?.config_sha256 && report.value.config_sha256 !== props.capture.config_sha256)
const statusText = (value: unknown) => protocolStatus[value as ProtocolStatus] ?? '尚未核实'
const cellStatus = (row: Record<string, unknown>, key: unknown) => statusText(typeof key === 'string' ? row[key] : undefined)
const cellClass = (row: Record<string, unknown>, key: unknown) => {
  const value = typeof key === 'string' ? row[key] : undefined
  return value === 'configured' ? 'status status-online' : ['detection_only','partial','requires_validation'].includes(String(value)) ? 'status status-medium' : ['native_listed','packet_headers_only'].includes(String(value)) ? 'status protocol-native' : 'status status-unknown'
}
const columns = [
  {title:'协议', key:'name', width:160, fixed:'left' as const},
  {title:'识别', dataIndex:'recognition', width:150}, {title:'事务与日志', dataIndex:'transactions', width:150},
  {title:'在线规则', dataIndex:'online_rules', width:165}, {title:'文件提取', dataIndex:'file_extraction', width:125},
  {title:'报文取证', dataIndex:'packet_forensics', width:150}, {title:'外部补充', dataIndex:'external_logs', width:125},
  {title:'操作', key:'actions', width:80, fixed:'right' as const},
]
watch(() => props.report, () => { selected.value = ''; sourceOpen.value = false })
</script>
<template>
  <a-alert v-if="!report" type="info" show-icon message="尚无可核对的协议能力观测，请刷新采集器状态；旧采集器可能尚未上报此信息。" />
  <a-alert v-else-if="report.state!=='observed'" type="warning" show-icon :message="protocolErrors[report.error_code??'']??'协议能力尚未核实，请刷新后核对。'" />
  <template v-else>
    <a-alert type="info" show-icon class="section-gap" message="配置状态不等于检测效果。TLS、QUIC 的可见握手不代表解密；规则命中、完整事务、文件提取和真实效果需分别验收。" />
    <a-alert v-if="changed" type="warning" show-icon class="section-gap" message="当前采集配置与此观测摘要不一致，请刷新后核对；本目录保留原观测来源。" />
    <a-alert v-else-if="report.source==='offline_template'||!report.capture_active" type="warning" show-icon class="section-gap" :message="report.source==='offline_template'?'此观测来自离线配置模板，不能确认外部 EVE 生产进程的实际启用状态。':'核对时未确认托管检测进程处于采集状态，配置不能证明正在检测。'" />
    <div class="protocol-context section-gap"><span>Suricata {{report.engine_version}} · {{report.source==='managed_configuration'?'托管检测配置':'离线配置模板'}}</span><span class="page-description">观测 {{formatTime(report.observed_at)}}</span><a-button type="link" @click="sourceOpen=true">查看来源</a-button></div>
    <div class="protocol-toolbar section-gap"><a-input v-model:value="query" aria-label="筛选协议" placeholder="协议名称或标识" allow-clear :maxlength="128" class="protocol-search" /><span class="page-description">{{rows.length}} / {{report.protocols.length}} 项 · 效果均待独立验证</span></div>
    <a-table class="protocol-table" row-key="protocol" table-layout="fixed" :columns="columns" :data-source="rows" :scroll="{x:1205}" :pagination="{pageSize:10,showSizeChanger:false,showTotal:(total:number)=>`共 ${total} 项`}" size="small" :locale="{emptyText:'没有匹配的协议'}">
      <template #bodyCell="{column,record}">
        <template v-if="column.key==='name'"><strong>{{record.name}}</strong><div class="technical page-description">{{record.protocol}}</div></template>
        <a-button v-else-if="column.key==='actions'" type="link" :aria-label="`查看 ${record.name} 协议能力`" @click="selected=record.protocol">查看</a-button>
        <span v-else :class="cellClass(record,column.dataIndex)">{{cellStatus(record,column.dataIndex)}}</span>
      </template>
    </a-table>
    <details class="protocol-limits section-gap"><summary>检测限额与配置边界</summary><a-descriptions bordered size="small" :column="1" class="section-gap"><a-descriptions-item v-for="limit in report.limits" :key="limit.key" :label="protocolLimitNames[limit.key]">{{limit.value||'未在此配置中显式设置，实际默认值需核查'}}</a-descriptions-item></a-descriptions><p class="page-description">仅展示白名单中的显式值，不包含 include、插件或规则效果推断。0 的含义依配置项而定，不代表没有内存、解压或事务限制。HTTP 站点专用配置可能覆盖默认正文深度；上限、缺包和加密都可能形成检测盲区。</p></details>
    <a-modal title="协议能力详情" :open="!!detail" :footer="null" :width="680" @cancel="selected=''">
      <ProtocolCapabilityDetails v-if="detail" :entry="detail" />
    </a-modal>
    <a-modal v-if="sourceOpen" title="协议能力来源" :open="true" :footer="null" :width="720" @cancel="sourceOpen=false"><a-descriptions bordered size="small" :column="1"><a-descriptions-item label="观测来源">{{report.source==='managed_configuration'?'托管检测配置':'离线配置模板'}} · Suricata {{report.engine_version}}</a-descriptions-item><a-descriptions-item label="观测时间">{{formatTime(report.observed_at)}}</a-descriptions-item><a-descriptions-item label="引擎文件摘要"><span class="technical protocol-digest">{{report.engine_sha256}}</span></a-descriptions-item><a-descriptions-item label="检测配置摘要"><span class="technical protocol-digest">{{report.config_sha256}}</span></a-descriptions-item></a-descriptions><p class="page-description section-gap">摘要绑定核对时的文件字节，不是运行进程、协议效果或发布资格的证明。请结合探针在线状态和当前采集配置核查。</p></a-modal>
  </template>
</template>
<style scoped>
.section-gap{margin-bottom:var(--section-gap,12px)}.protocol-context,.protocol-toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.protocol-context{font-size:13px}.protocol-search{max-width:320px}.protocol-digest{overflow-wrap:anywhere}.protocol-table{min-width:0}.status{display:inline-block;border-radius:4px;padding:1px 7px;white-space:nowrap;font-size:12px;line-height:1.7}.status-online{color:var(--success);background:var(--success-surface)}.status-medium{color:var(--warning);background:var(--warning-surface)}.status-unknown{color:var(--status-text);background:var(--status-surface)}.protocol-native{color:var(--link);background:var(--info-surface)}.protocol-limits{min-width:0}.protocol-limits summary{cursor:pointer;font-weight:500}.protocol-limits summary:focus-visible{outline:2px solid var(--primary);outline-offset:4px}
</style>
