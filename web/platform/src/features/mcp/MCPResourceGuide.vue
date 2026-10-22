<script setup lang="ts">
import {onScopeDispose,shallowRef} from 'vue'
import {Alert,Button} from 'ant-design-vue'

const resources=[
  {name:'告警检索字段',uri:'starbeacon://catalog/alerts/fields',scope:'alerts:read',description:'告警数据集支持的字段、别名、类型与运算符。'},
  {name:'协议检索字段',uri:'starbeacon://catalog/context/fields',scope:'traffic:read',description:'协议数据集支持的字段、别名、类型与运算符。'},
  {name:'分析能力说明',uri:'starbeacon://catalog/capabilities',scope:'任一已授权只读权限',description:'当前身份获授权的工具、数据集、资源与请求限制。'},
] as const
const template='starbeacon://catalog/{dataset}/fields'
const copying=shallowRef(''),copied=shallowRef(''),copyError=shallowRef('')
let disposed=false
onScopeDispose(()=>{disposed=true})

async function copy(value:string){
  if(copying.value)return
  copying.value=value;copied.value='';copyError.value=''
  try{
    if(!navigator.clipboard)throw new Error('clipboard unavailable')
    await navigator.clipboard.writeText(value)
    if(!disposed)copied.value=value
  }catch{
    if(!disposed)copyError.value='无法访问剪贴板，请选择资源地址后手动复制。'
  }finally{if(!disposed)copying.value=''}
}
</script>
<template>
  <section class="mcp-resource-guide" aria-label="MCP 元数据资源接入说明">
    <Alert type="info" show-icon message="以下为资源接入说明，不是当前身份的发现结果。" description="Agent 应使用自己的令牌调用 resources/list；返回范围由令牌与服务身份的有效权限共同决定。" />
    <Alert v-if="copyError" type="error" show-icon :message="copyError" />
    <dl class="mcp-resource-list">
      <div v-for="resource in resources" :key="resource.uri" class="mcp-resource-entry">
        <dt class="mcp-resource-heading"><strong>{{resource.name}}</strong><Button size="small" :aria-label="'复制'+resource.name+'地址'" :loading="copying===resource.uri" :disabled="!!copying&&copying!==resource.uri" @click="copy(resource.uri)">{{copied===resource.uri?'已复制':'复制地址'}}</Button></dt>
        <dd class="mcp-resource-content"><code class="mcp-resource-uri">{{resource.uri}}</code><p class="mcp-resource-description">{{resource.description}}</p><span class="muted">需要权限：{{resource.scope}}</span></dd>
      </div>
    </dl>
    <div class="mcp-resource-template">
      <h3 class="mcp-guide-title">字段资源模板</h3>
      <div class="mcp-template-address"><code class="mcp-resource-uri">{{template}}</code><Button size="small" aria-label="复制字段资源模板" :loading="copying===template" :disabled="!!copying&&copying!==template" @click="copy(template)">{{copied===template?'已复制':'复制模板'}}</Button></div>
      <p class="mcp-resource-description"><code>dataset</code> 仅支持 <code>alerts</code>、<code>context</code>。需要相应数据集的只读权限；字段目录不表示字段已被采集或索引。</p>
    </div>
    <div>
      <h3 class="mcp-guide-title">调用方式与边界</h3>
      <ol class="mcp-resource-steps"><li>完成 MCP 初始化后，调用 <code>resources/list</code> 获取当前身份可访问的资源。</li><li>调用 <code>resources/templates/list</code> 核对可用模板；没有字段数据集权限时不返回字段模板。</li><li>使用发现结果中的完整 URI 调用 <code>resources/read</code>，按 <code>application/json</code> 解析 <code>contents[].text</code>。</li></ol>
      <p class="mcp-resource-description">读取结果包含数据、观测时间、请求标识和限制说明；能力说明的版本为 <code>mcp-metadata.v1</code>。发现与读取和工具共用身份、租户预算及操作审计，单次请求最多 64 KiB、内容最多 256 KiB、执行上限 10 秒。</p>
      <p class="mcp-resource-description">资源只描述授权范围内的软件能力，不提供原始载荷、PCAP、任意文件下载或设备执行权限。使用字段目录后仍需独立检索，不能据此认定已有数据、攻击成功或生产兼容性已验收。</p>
    </div>
  </section>
</template>
<style scoped>
.mcp-resource-guide{display:grid;gap:var(--section-gap)}.mcp-resource-list{display:grid;gap:var(--related-gap);margin:0}.mcp-resource-entry{border-bottom:1px solid var(--line);padding-bottom:var(--related-gap)}.mcp-resource-heading,.mcp-template-address{display:flex;align-items:center;justify-content:space-between;gap:var(--related-gap)}.mcp-resource-content{margin:var(--related-gap) 0 0}.mcp-resource-uri{overflow-wrap:anywhere;word-break:break-word;user-select:text}.mcp-resource-description{margin:var(--related-gap) 0 0}.mcp-guide-title{margin:0 0 var(--related-gap);font-size:14px;font-weight:600}.mcp-resource-steps{margin:0;padding-left:20px}.mcp-resource-steps li+li{margin-top:var(--related-gap)}.mcp-template-address{align-items:flex-start}.mcp-resource-heading>button,.mcp-template-address>button{flex-shrink:0}@media(max-width:640px){.mcp-resource-heading,.mcp-template-address{align-items:flex-start;flex-wrap:wrap}}
</style>
