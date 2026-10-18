<script setup lang="ts">
import {computed} from 'vue'
import {Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem,Tag as ATag} from 'ant-design-vue'
import {engineHealthReason,engineHealthStates,readEngineHealth} from '../engineHealth'
import {formatTime} from '../types'
const props=defineProps<{report?:unknown}>()
const observation=computed(()=>readEngineHealth(props.report))
const title=computed(()=>observation.value?engineHealthStates[observation.value.state]:props.report?'观测数据无法核对':'尚无原生观测')
const color=computed(()=>observation.value?.state==='observed'?'success':observation.value?.state==='unavailable'?'error':'default')
</script>
<template>
 <section class="panel section-gap engine-observation" aria-label="检测引擎观测">
  <header class="panel-header"><h3>检测引擎观测</h3><a-tag :color="color">{{title}}</a-tag></header>
  <div class="panel-body">
   <p v-if="!observation" class="page-description">{{report?'返回的观测格式不完整，无法确认进程及规则装载状态。':'设备尚未上报原生进程与规则装载观测，登记文件摘要不能代替该项核对。'}}</p>
   <template v-else>
    <p class="page-description">{{engineHealthReason(observation.code)}} · {{formatTime(observation.observed_at)}}</p>
    <a-descriptions v-if="observation.state==='observed'" bordered size="small" :column="1">
     <a-descriptions-item label="进程来源">{{observation.source==='managed_process'?'托管检测进程':'登记检测进程'}} · PID {{observation.pid}}</a-descriptions-item>
     <a-descriptions-item label="进程启动时间">{{formatTime(observation.started_at)}}</a-descriptions-item>
     <a-descriptions-item label="规则装载计数">已装载 {{observation.rules_loaded}} 条 / 文件 {{observation.file_rule_count}} 条 · 装载失败 {{observation.rules_failed}} 条</a-descriptions-item>
     <a-descriptions-item label="登记规则文件摘要"><span class="technical engine-digest">{{observation.rules_sha256}}</span></a-descriptions-item>
     <a-descriptions-item label="配置文件摘要"><span class="technical engine-digest">{{observation.config_sha256}}</span></a-descriptions-item>
    </a-descriptions>
   </template>
   <p class="field-hint">原生状态只反映本次观测。规则文件摘要和装载数量不证明引擎内存中的规则内容相同，也不代表持续吞吐或检测效果通过验收。</p>
  </div>
 </section>
</template>
<style scoped>
.engine-observation{margin-bottom:12px}.panel-header{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;padding:12px 14px;border-bottom:1px solid var(--line)}.panel-header h3{margin:0;font-size:14px}.panel-header .ant-tag{margin:0}.panel-body{padding:12px 14px}.engine-digest{overflow-wrap:anywhere;word-break:break-all}.page-description{margin:0 0 10px}.field-hint{margin:10px 0 0}
</style>
