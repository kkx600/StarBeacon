<script setup lang="ts">
import { Descriptions as ADescriptions } from 'ant-design-vue'
import type { ProtocolEntry } from '../protocols'
const ADescriptionsItem = ADescriptions.Item
defineProps<{entry:ProtocolEntry}>()
const bindingMode:Record<string,string>={yes:'显式启用',no:'显式禁用','detection-only':'仅识别',unknown:'未显式配置'}
</script>
<template>
  <a-descriptions bordered :column="1" size="small">
    <a-descriptions-item label="协议">{{entry.name}} · {{entry.protocol}}</a-descriptions-item>
    <a-descriptions-item label="本配置原生目录">{{entry.native_listed?'已列出':'未列出；可能受配置、构建或版本影响'}}</a-descriptions-item>
    <a-descriptions-item label="传输层配置"><div v-for="binding in entry.bindings" :key="binding.transport">{{binding.transport==='unknown'?'传输层待核查':binding.transport.toUpperCase()}} · {{bindingMode[binding.mode]}}</div><span v-if="!entry.bindings.length">不适用应用层解析器配置</span></a-descriptions-item>
    <a-descriptions-item label="效果资格">未完成独立正反例及非标准端口验收</a-descriptions-item>
  </a-descriptions>
  <p class="page-description section-gap">“原生目录已列出”不能单独证明事务解析已启用；“已配置”也不证明当前流量存在、完整可见或规则有效。目录不授予文件下载、模型调用或设备动作权限。</p>
</template>
