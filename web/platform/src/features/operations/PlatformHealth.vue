<script setup lang="ts">
import {computed,onMounted,onScopeDispose,shallowRef} from 'vue'
import {Descriptions as ADescriptions} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatPercent,formatTime,formatHealthErrors,type PlatformHealth} from '@starbeacon/shared/types.ts'
import {formatBytes} from '@starbeacon/shared/utils/format.ts'
import {session} from '../../session'
const ADescriptionsItem=ADescriptions.Item
const result=shallowRef<PlatformHealth|null>(null),pending=shallowRef(true),error=shallowRef('')
const serviceNames:Record<string,string>={postgresql:'平台数据库',redis:'缓存与登录限流',elasticsearch:'告警检索',packet_storage:'原包存储'}
const backendNames:Record<string,string>={filesystem:'本地或挂载文件系统',s3:'S3 兼容对象存储'}
const unavailable=computed(()=>result.value&&Object.values(result.value.services).some(state=>state!=='ready'))
// 原包存储由全部租户共享：容量来自部署存储，原包数量与可回溯时间只统计当前租户。
const storage=computed(()=>result.value?.packet_storage)
const amount=(value:string)=>/^\d{1,20}$/.test(value)?BigInt(value):null
const count=(value:string)=>amount(value)?.toLocaleString('zh-CN')??'未获取'
const pressure=computed(()=>{const value=storage.value;if(!value?.measured)return false;const free=amount(value.free_bytes),floor=amount(value.floor_bytes);return free!==null&&floor!==null&&free<floor})
const limited=computed(()=>(amount(storage.value?.limit_bytes??'')??0n)>0n)
const reach=computed(()=>{const oldest=storage.value?.oldest_created_at,observed=result.value?.observed_at;if(!oldest||!observed)return '';const days=Math.max(0,(Date.parse(observed)-Date.parse(oldest))/86400000);return Number.isFinite(days)?`${days<10?days.toFixed(1):Math.floor(days)} 天`:''})
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
    <section v-if="storage" class="panel packet-storage" aria-labelledby="packet-storage-title"><div class="panel-header"><h2 id="packet-storage-title">原包存储</h2><span class="page-description">{{backendNames[storage.backend]??storage.backend}}，全部租户共享</span></div>
      <div class="metric-grid">
        <div><span>共享剩余空间</span><strong>{{storage.measured?formatBytes(storage.free_bytes,true):'无法测量'}}</strong><small>{{storage.measured?`总容量 ${formatBytes(storage.total_bytes,true)}`:'对象存储不提供剩余空间'}}</small></div>
        <div v-if="storage.measured"><span>回收阈值</span><strong>{{formatBytes(storage.floor_bytes,true)}}</strong><small>{{limited?`剩余低于该值或总量超过 ${formatBytes(storage.limit_bytes,true)} 时回收`:'剩余低于该值时回收最早原包'}}</small></div>
        <div v-else><span>目录上限</span><strong>{{limited?formatBytes(storage.limit_bytes,true):'不限'}}</strong><small>{{limited?'总量超过上限时回收最早原包':'未设置上限，只按保留期删除'}}</small></div>
        <div><span>本租户原包</span><strong>{{count(storage.archives)}}</strong><small>占用 {{formatBytes(storage.stored_bytes,true)}}</small></div>
        <div><span>实际可回溯</span><strong>{{reach||'暂无原包'}}</strong><small>{{storage.oldest_created_at?`最早 ${formatTime(storage.oldest_created_at)}，`:''}}保留期上限 {{storage.retention_days}} 天</small></div>
      </div>
      <div class="panel-body"><a-alert v-if="pressure" type="warning" show-icon class="section-gap" message="共享存储剩余空间低于回收阈值，平台正在按全部租户最早归档的顺序回收原包；需要更长回溯时请扩容存储。"/><p class="page-description">原包存储不设租户额度，可回溯范围由部署存储容量和流量决定。空间不足时先回收全部租户中最早归档的原包，正在下载或导出的原包会跳过；保留期是每个原包的最长期限。</p></div>
    </section>
    <section class="panel"><div class="panel-header"><h2>运行信息</h2></div><div class="panel-body"><a-descriptions size="small" :column="1"><a-descriptions-item label="版本">{{result.runtime.version}}</a-descriptions-item><a-descriptions-item label="提交标识"><span class="technical">{{result.runtime.commit}}</span></a-descriptions-item><a-descriptions-item label="运行协程">{{result.runtime.goroutines.toLocaleString('zh-CN')}}</a-descriptions-item></a-descriptions><p class="page-description">依赖可用性不代表采集质量、队列容量或整体性能已经符合要求。</p></div></section>
  </template></StatePanel>
</template>
<style scoped>.platform-services {display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--section-gap);padding:0 var(--panel-inset) var(--panel-inset)}.platform-services>div {display:flex;align-items:center;justify-content:space-between;gap:var(--related-gap);border:1px solid var(--line);border-radius:6px;padding:var(--section-gap);min-width:0;flex-wrap:wrap}.packet-storage .panel-header {flex-wrap:wrap;justify-content:flex-start}.packet-storage .metric-grid {padding-top:0}</style>
