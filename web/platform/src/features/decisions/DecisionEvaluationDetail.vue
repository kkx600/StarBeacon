<script setup lang="ts">
import {Modal as AModal} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {policyActions,policyStatuses,policyReasons} from './decisionPolicies'
import type {EvaluationRecord} from './decisionEvaluations'
defineProps<{record:EvaluationRecord;canRespond?:boolean}>();defineEmits<{close:[];respond:[record:EvaluationRecord]}>()
</script>
<template>
 <a-modal :open="true" title="评估记录详情" :width="820" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="$emit('close')">
  <a-alert type="info" show-icon message="本记录保存评估时的策略和判断快照。历史结果未授权执行，不代表当前策略或攻击处置效果。" class="section-gap"/>
  <dl class="evaluation-detail">
   <dt>评估标识</dt><dd class="technical">{{record.id}}</dd><dt>判断结果</dt><dd>{{policyStatuses[record.result.status]}} · 未授权执行</dd>
   <dt>策略 / 修订</dt><dd>{{record.policy.name}} / {{record.policy.revision}}</dd><dt>判断依据</dt><dd>{{record.result.reasons.map(x=>policyReasons[x]).join('；')}}</dd>
   <dt>候选处置 / 目标</dt><dd>{{policyActions[record.result.candidate_action]}} / {{record.result.target_ip||'无'}}</dd><dt>模型自报分数</dt><dd>{{record.result.confidence===null?'未参与评估':record.result.confidence.toFixed(3)}} · 未校准</dd>
   <dt>评估 / 保留截止</dt><dd>{{formatTime(record.result.evaluated_at)}} / {{formatTime(record.expires_at)}}</dd><dt>研判作业</dt><dd class="technical">{{record.result.triage_id}}</dd><dt>模型 / 修订</dt><dd>{{record.result.provider_id}} / {{record.result.provider_revision}}</dd>
   <dt>告警标识</dt><dd class="technical">{{record.result.event_id}}</dd><dt>材料 SHA-256</dt><dd class="technical">{{record.result.evidence_sha256}}</dd><dt>原始事件 SHA-256</dt><dd class="technical">{{record.result.raw_sha256}}</dd><dt>策略 SHA-256</dt><dd class="technical">{{record.result.definition_sha256}}</dd><dt>档案 SHA-256</dt><dd class="technical">{{record.sha256}}</dd>
  </dl>
  <h3>判断表达式</h3><pre class="evaluation-expression">{{record.policy.definition.expression}}</pre>
  <h3>证据与执行限制</h3><ul><li v-for="item in record.result.limitations" :key="item">{{item}}</li></ul>
  <div v-if="canRespond&&record.result.status==='matched'&&record.result.candidate_action==='block_source'&&record.result.target_ip" class="filter-actions"><a-button type="primary" @click="$emit('respond',record)">处置确认</a-button></div>
 </a-modal>
</template>
<style scoped>.evaluation-detail{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px}.evaluation-detail dt{color:var(--text-secondary,#4b5563)}.evaluation-detail dd{margin:0;overflow-wrap:anywhere}.evaluation-expression{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:var(--surface-muted,#f8f9fa);border:1px solid var(--border-color,#e5e7eb);border-radius:8px}@media(max-width:1100px){.evaluation-detail{grid-template-columns:130px minmax(0,1fr)}}</style>
