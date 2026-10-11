<script setup lang="ts">
import {computed,onMounted,onScopeDispose,shallowRef} from 'vue'
import {Descriptions as ADescriptions} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatPercent,formatTime,formatHealthErrors,type PlatformHealth} from '@starbeacon/shared/types.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import {session} from '../../session'
const ADescriptionsItem=ADescriptions.Item
const result=shallowRef<PlatformHealth|null>(null),pending=shallowRef(true),error=shallowRef('')
const serviceNames:Record<string,string>={postgresql:'平台数据库',redis:'缓存与登录限流',elasticsearch:'告警检索'}
const unavailable=computed(()=>result.value&&Object.values(result.value.services).some(state=>state!=='ready'))
let controller:AbortController|undefined
async function refresh(){controller?.abort();const active=new AbortController();controller=active;pending.value=true;error.value='';try{const value=await session.api.request<PlatformHealth>('/platform/health',{signal:active.signal});if(!active.signal.aborted)result.value=value}catch(e){if(!active.signal.aborted)error.value=e instanceof Error?e.message:'运行状态读取失败'}finally{if(controller===active)pending.value=false}}
onMounted(refresh);onScopeDispose(()=>controller?.abort())
</script>
<template>
  <div class="filter-actions section-gap"><a-button :loading="pending" @click="refresh">刷新运行状态</a-button><span class="page-description">{{result?`观测时间 ${formatTime(result.observed_at)}`:'等待平台观测'}}</span></div>
  <StatePanel :loading="pending" :error="error" @retry="refresh"><template v-if="result">
    <a-alert v-if="unavailable" type="warning" message="部分平台依赖不可用，相关操作可能无法完成，请核对服务状态。" show-icon class="section-gap"/>
    <a-alert v-if="result.runtime.errors.length" :message="formatHealthErrors(result.runtime.errors)" type="warning" show-icon class="section-gap"/>
    <section class="panel"><div class="metric-grid"><div><span>CPU 使用率</span><strong>{{formatPercent(result.runtime.cpu_percent)}}</strong><small>所在运行环境观测</small></div><div><span>内存使用率</span><strong>{{formatPercent(result.runtime.memory_percent)}}</strong><small>所在运行环境观测</small></div><div><span>磁盘使用率</span><strong>{{formatPercent(result.runtime.disk_percent)}}</strong><small>进程工作目录所在磁盘</small></div><div><span>进程堆内存</span><strong>{{formatBytes(result.runtime.heap_bytes)}}</strong><small>平台进程实际分配</small></div></div></section>
    <section class="panel"><div class="panel-header"><h2>依赖服务</h2></div><div class="platform-services"><div v-for="(state,name) in result.services" :key="name"><span>{{serviceNames[String(name)]??name}}</span><span :class="['status',state==='ready'?'status-online':'status-high']">{{state==='ready'?'可用':'不可用'}}</span></div></div></section>
    <section class="panel"><div class="panel-header"><h2>运行信息</h2></div><div class="panel-body"><a-descriptions size="small" :column="1"><a-descriptions-item label="版本">{{result.runtime.version}}</a-descriptions-item><a-descriptions-item label="提交标识"><span class="technical">{{result.runtime.commit}}</span></a-descriptions-item><a-descriptions-item label="运行协程">{{result.runtime.goroutines.toLocaleString('zh-CN')}}</a-descriptions-item></a-descriptions><p class="page-description">依赖可用性不代表采集质量、队列容量或整体性能已经符合要求。</p></div></section>
  </template></StatePanel>
</template>
<style scoped>.platform-services {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--section-gap);padding:0 var(--panel-inset) var(--panel-inset)}.platform-services>div {display:flex;align-items:center;justify-content:space-between;gap:var(--related-gap);border:1px solid var(--line);border-radius:6px;padding:var(--section-gap);min-width:0;flex-wrap:wrap}@media(max-width:900px){.platform-services {grid-template-columns:minmax(0,1fr)}}</style>
