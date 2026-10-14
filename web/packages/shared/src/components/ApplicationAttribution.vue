<script setup lang="ts">
import {computed} from 'vue'
import {Tag as ATag} from 'ant-design-vue'
import {applicationStatuses,applicationReasons,applicationCategoryNames,validApplicationAttribution,type ApplicationAttribution} from '../application'
import {formatTime} from '../types'
const props=defineProps<{attribution?:ApplicationAttribution;rawDigest:string;observed:string}>()
const record=computed(()=>props.attribution&&validApplicationAttribution(props.attribution,props.rawDigest,props.observed)?props.attribution:null)
</script>
<template>
 <section class="application-evidence" aria-label="应用识别依据">
  <h2>应用识别</h2>
  <p v-if="!attribution" class="muted">当前记录未提供可核验的应用分类。协议名称不表示具体产品。</p>
  <a-alert v-else-if="!record" type="error" show-icon message="应用分类回执不完整或与当前记录不一致，无法展示产品归因。"/>
  <template v-else>
   <p><a-tag :color="record.result.status==='candidate'?'blue':record.result.status==='conflict'?'orange':undefined">{{applicationStatuses[record.result.status]}}</a-tag>{{applicationReasons[record.result.reason]}}</p>
   <dl class="application-facts"><dt>产品 / 类别</dt><dd>{{record.product_name||'无法唯一归因'}} / {{applicationCategoryNames[record.category_id]||'未归类'}}</dd><dt>规则快照</dt><dd>{{record.result.rule_count}} 条部署规则 · {{record.result.matched_rule_count}} 条命中</dd><dt>分类时间</dt><dd>{{formatTime(record.result.evaluated_at)}}</dd><dt>部署任务</dt><dd class="technical">{{record.deployment_id}}</dd><dt>快照 SHA-256</dt><dd class="technical">{{record.result.rules_sha256}}</dd></dl>
   <ul v-if="record.result.matches.length" class="application-evidence-list"><li v-for="match in record.result.matches" :key="match.rule_id"><strong>{{match.product_name}}</strong> · <span class="technical">{{match.rule_id}}</span> / 修订 {{match.revision}}<ul><li v-for="(evidence,index) in match.evidence" :key="index" class="technical">{{evidence.field}} · {{evidence.op}} · {{evidence.pattern}}</li></ul><span v-if="match.evidence_limited" class="muted">依据达到展示预算，仅展示部分条件。</span></li></ul>
   <p v-if="record.result.limited" class="muted">仅展示前 16 条命中，分类状态已考虑全部命中规则。</p>
   <p class="muted">分类基于本条协议事件的可见元数据，不能证明密文已解密、攻击成功或对应应用的通信字节数；DNS 名称不会扩散到其他连接。</p>
  </template>
 </section>
</template>
<style scoped>
.application-evidence{margin:12px 0}.application-evidence h2{font-size:16px;margin:0 0 8px}.application-facts{display:grid;grid-template-columns:120px minmax(0,1fr);gap:8px}.application-facts dt{color:var(--text-secondary,#4b5563)}.application-facts dd{margin:0;overflow-wrap:anywhere}.application-evidence-list{padding-left:20px}.application-evidence-list li{margin:4px 0;overflow-wrap:anywhere}.technical{overflow-wrap:anywhere}
</style>
