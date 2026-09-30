<script setup lang="ts">
import type {BusinessRecord} from '../models'
import {exportJson} from '../composables/useRecords'
import StatusTag from './StatusTag.vue'
defineProps<{record:BusinessRecord;tab:string}>()
</script>
<template>
  <a-descriptions v-if="tab==='任务信息'" bordered :column="{xs:1,sm:1,md:2}" size="small">
    <a-descriptions-item label="任务 ID">{{record.id}}</a-descriptions-item><a-descriptions-item label="任务状态"><StatusTag :value="record.status"/></a-descriptions-item>
    <a-descriptions-item label="会话 ID">{{record.session??'未关联'}}</a-descriptions-item><a-descriptions-item label="导出模式">{{record.mode??'未配置'}}</a-descriptions-item>
    <a-descriptions-item label="格式">{{record.format??'未配置'}}</a-descriptions-item><a-descriptions-item label="网络域">{{record.scope??'未配置'}}</a-descriptions-item>
  </a-descriptions>
  <template v-else-if="tab==='会话完整性'">
    <a-descriptions bordered :column="1" size="small"><a-descriptions-item label="真实三次握手">{{record.handshake??'未验证'}}</a-descriptions-item><a-descriptions-item label="双向字节连续性">{{record.continuity??'未验证'}}</a-descriptions-item><a-descriptions-item label="连接结束">{{record.closure??'未验证'}}</a-descriptions-item></a-descriptions>
    <p class="field-hint">完整会话导出需要逐项通过验证。观测快照保留已见数据及缺口说明；不补造握手、载荷或连接结束包。</p>
  </template>
  <template v-else>
    <a-descriptions bordered :column="{xs:1,sm:1,md:2}" size="small"><a-descriptions-item label="下载授权到期">{{record.expires??'尚未授权'}}</a-descriptions-item><a-descriptions-item label="文件体积">未提供真实导出对象</a-descriptions-item><a-descriptions-item label="对象引用">{{record.exportObject??'未生成'}}</a-descriptions-item><a-descriptions-item label="SHA-256">{{record.digest??'待真实文件生成后计算'}}</a-descriptions-item></a-descriptions>
    <p class="field-hint">任务状态为合成示例。当前没有真实 PCAP 文件；生产下载需要任务完成、会话完整性、对象及当前授权同时满足。</p>
    <a-space style="margin-top:16px"><a-button disabled>下载 PCAP</a-button><a-button @click="exportJson(record.id,{synthetic:true,record})">导出证据清单</a-button></a-space>
  </template>
</template>
