<script setup lang="ts">
import {shallowRef,watch} from 'vue'
import {Modal as AModal,Table as ATable} from 'ant-design-vue'
import StatePanel from './StatePanel.vue'
import {discoveryCount,discoveryEndpoint,type DiscoveryResult,type DiscoveryAddress} from '../discovery'
const props=defineProps<{result:DiscoveryResult|null;pending:boolean;error:string;attempted:boolean;canRegister?:boolean;initialIP?:string}>()
const emit=defineEmits<{retry:[];register:[row:DiscoveryAddress,result:DiscoveryResult]}>()
const selected=shallowRef<DiscoveryAddress|null>(null)
watch(()=>[props.result,props.initialIP],()=>{selected.value=props.result?.addresses.find(row=>row.ip===props.initialIP)??null},{immediate:true})
const columns=[{title:'观测 IP',key:'ip',width:190,fixed:'left' as const},{title:'源方向流记录',key:'source',width:145},{title:'目的方向流记录',key:'destination',width:150},{title:'首次记录时间',key:'first',width:260},{title:'末次记录时间',key:'last',width:260},{title:'操作',key:'actions',width:200,fixed:'right' as const}]
</script>
<template>
 <section class="panel discovery-panel">
  <div class="panel-header"><h2>地址观测</h2><span v-if="result">{{result.addresses.length}} 个地址</span></div>
   <div v-if="result&&!pending&&!error" class="discovery-summary"><strong>{{result.scope.network_name}} · {{result.scope.network_domain}}</strong><span>{{result.scope.sensor_name}} · {{result.query.prefix}}</span><span>查询窗口：{{result.query.start}} 至 {{result.query.end}}（结束时刻不包含）</span><span>排除的组播、未指定及全局广播方向记录：源 {{discoveryCount(result.source_excluded)}} / 目的 {{discoveryCount(result.destination_excluded)}}</span></div>
  <StatePanel :loading="pending" :error="error" :empty="!result||result.addresses.length===0" :description="!attempted?'选择探针、网段和时间窗口后执行发现。':result?.partition_status==='absent'?'当前租户尚无可查询的流量分区，请核对采集与索引状态。':'当前范围未观测到可列出的地址，请核对探针、时间窗口和采集覆盖。'" @retry="emit('retry')">

   <a-table :columns="columns" :data-source="result?.addresses??[]" row-key="ip" :pagination="{pageSize:20,showSizeChanger:false,hideOnSinglePage:true}" :scroll="{x:1205}">
    <template #bodyCell="{column,record}"><a-button v-if="column.key==='ip'" class="discovery-address" type="link" @click="selected=record as DiscoveryAddress">{{record.ip}}</a-button><span v-else-if="column.key==='source'" class="discovery-count">{{discoveryCount(record.source_records)}}</span><span v-else-if="column.key==='destination'" class="discovery-count">{{discoveryCount(record.destination_records)}}</span><code v-else-if="column.key==='first'">{{record.first.timestamp}}</code><code v-else-if="column.key==='last'">{{record.last.timestamp}}</code><div v-else-if="column.key==='actions'" class="filter-actions"><a-button type="link" @click="selected=record as DiscoveryAddress">证据</a-button><a-button v-if="canRegister&&result" type="link" @click="emit('register',record as DiscoveryAddress,result)">登记资产</a-button></div></template>
   </a-table>
  </StatePanel>
 </section>
 <a-modal v-if="selected&&result" open title="地址观测证据" :width="860" :footer="null" @cancel="selected=null">
  <a-alert type="info" show-icon message="IP 与 MAC 来自流记录端点；网关、NAT、DHCP 和镜像位置会影响观测，不能据此认定资产身份或接口归属。" class="section-gap"/>
  <dl class="discovery-facts"><dt>观测地址</dt><dd>{{selected.ip}}</dd><dt>探针 / 注册标识</dt><dd>{{result.scope.sensor_name}} / {{result.scope.registration_id}}</dd><dt>网络域 / 网段修订</dt><dd>{{result.scope.network_domain}} / {{result.scope.network_name}} · {{result.scope.network_revision}}</dd></dl>
  <section v-for="(sample,index) in [selected.first,selected.last]" :key="index" class="discovery-evidence"><h3>{{index===0?'首次记录':'末次记录'}} · {{sample.side==='source'?'源方向':'目的方向'}}</h3><dl class="discovery-facts"><dt>事件时间</dt><dd><code>{{sample.timestamp}}</code></dd><dt>采集器读取时间</dt><dd><code>{{sample.observed_at}}</code></dd><dt>源端点</dt><dd>{{discoveryEndpoint(sample.source)}} · MAC {{sample.source.mac||'未记录'}}</dd><dt>目的端点</dt><dd>{{discoveryEndpoint(sample.destination)}} · MAC {{sample.destination.mac||'未记录'}}</dd><dt>事件 / 流标识</dt><dd>{{sample.event_id}} / {{sample.flow_id}}</dd><dt>源代次 / 序号</dt><dd>{{sample.generation_id}} / {{sample.sequence}}</dd><dt>原始记录 SHA-256</dt><dd><code>{{sample.raw_sha256}}</code></dd></dl></section>
  <div class="filter-actions"><a-button v-if="canRegister" type="primary" @click="emit('register',selected,result);selected=null">登记资产</a-button><a-button @click="selected=null">关闭</a-button></div>
 </a-modal>
</template>
<style scoped>
.panel-header{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:var(--panel-inset)}.panel-header h2{margin:0;font-size:16px}.filter-actions{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap)}.discovery-summary{display:flex;flex-direction:column;gap:6px;padding:0 var(--panel-inset) var(--section-gap);color:var(--muted);overflow-wrap:anywhere}.discovery-summary strong{color:var(--text)}.discovery-panel{min-width:0;overflow:hidden}.discovery-count{display:block;overflow-wrap:anywhere;white-space:normal;font-variant-numeric:tabular-nums}.discovery-address{height:auto;text-align:left;white-space:normal;overflow-wrap:anywhere;max-width:100%}.discovery-panel code{font-size:12px;white-space:normal;overflow-wrap:anywhere}.discovery-facts{display:grid;grid-template-columns:155px minmax(0,1fr);gap:8px 12px;margin:12px 0}.discovery-facts dt{color:var(--muted)}.discovery-facts dd{margin:0;overflow-wrap:anywhere}.discovery-evidence{border-top:1px solid var(--line);padding-top:12px;margin-top:12px}.discovery-evidence h3{margin:0;font-size:14px}@media(max-width:700px){.discovery-facts{grid-template-columns:minmax(0,1fr);gap:4px}.discovery-facts dd{margin-bottom:8px}}
</style>
