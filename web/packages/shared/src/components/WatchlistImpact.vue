<script setup lang="ts">
import {computed,reactive,watch} from 'vue'
import {Table as ATable,InputNumber as AInputNumber} from 'ant-design-vue'
import StatePanel from './StatePanel.vue'
import {localWatchlistTime,watchlistHitFields,watchlistKinds,watchlistSeverities,type WatchlistImpact} from '../watchlists'
import {formatTime} from '../types'
const props=defineProps<{listId:string;revision:number;maximum:number;result:WatchlistImpact|null;pending:boolean;error:string;incomplete:boolean}>()
const emit=defineEmits<{run:[revision:number,start:string,end:string];change:[]}>()
const form=reactive({revision:props.revision as number|null,start:localWatchlistTime(new Date(Date.now()-86400000)),end:localWatchlistTime(new Date(Date.now()))})
const validRevision=computed(()=>form.revision!==null&&Number.isSafeInteger(form.revision)&&form.revision>=1&&form.revision<=props.maximum)
const valueColumns=[{title:'匹配值',key:'value',width:320},{title:'命中数',key:'count',width:120}]
const sampleColumns=[{title:'告警观测时间',key:'observed',width:190},{title:'命中字段 / 值',key:'matches',width:260},{title:'告警规则',key:'rule',width:240},{title:'严重级别',key:'severity',width:100},{title:'探针 / 注册代次',key:'sensor',width:190}]
const fieldLabels=computed(()=>(props.result?.fields??[]).map(field=>watchlistHitFields[field as keyof typeof watchlistHitFields]??field))
function run(){if(!props.pending&&validRevision.value&&form.revision!==null)emit('run',form.revision,form.start,form.end)}
function choose(v:number|string|null){form.revision=v===null||v===''?null:Number(v)}
watch(()=>[props.listId,props.revision].join('/'),()=>{form.revision=props.revision;emit('change')})
watch(()=>[form.revision,form.start,form.end].join('/'),()=>emit('change'))
</script>
<template>
 <section aria-label="观察名单历史影响预览">
  <a-alert type="info" show-icon message="预览只核对已入索引的告警，不登记命中、不回填历史、不授予设备动作。TLS SNI 与 DNS 查询名没有检索字段，不在预览范围。" class="section-gap"/>
  <a-form :model="form" layout="vertical" class="panel panel-body watchlist-impact-form" @finish="run"><div class="watchlist-impact-fields">
   <a-form-item label="修订号" html-for="watchlist-impact-revision" required extra="按所选修订当时的定义核对。"><a-input-number id="watchlist-impact-revision" :value="form.revision??''" @update:value="choose" :min="1" :max="maximum" :precision="0" :disabled="pending"/></a-form-item>
   <a-form-item label="开始时间（本地时间）" html-for="watchlist-impact-start" required><a-input id="watchlist-impact-start" v-model:value="form.start" type="datetime-local" step="1"/></a-form-item>
   <a-form-item label="结束时间（本地时间）" html-for="watchlist-impact-end" required extra="结束时刻不包含在查询内，窗口最多 31 天。"><a-input id="watchlist-impact-end" v-model:value="form.end" type="datetime-local" step="1"/></a-form-item>
  </div><div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending" :disabled="pending||!validRevision">执行预览</a-button></div></a-form>
  <a-alert v-if="incomplete" type="error" show-icon message="历史检索结果不完整，本次未交付计数" description="本次核对未取得精确计数，已不显示任何部分数字。请稍后重试或缩小核对窗口。" class="section-gap"/>
  <StatePanel :loading="pending" :error="incomplete?'':error" @retry="run">
   <template v-if="result&&!incomplete">
    <!-- 预览不限定名单类型；保护名单只做只读核对，实时命中只对启用的观察名单登记。 -->
    <p class="page-description section-gap">{{watchlistKinds[result.kind]}} · 修订 {{result.list_revision}}{{result.current?'（当前修订）':'（历史修订）'}}<template v-if="result.kind==='protect'">；保护名单不会自动登记命中，本次结果仅用于核对。</template></p>
    <div class="panel"><div class="metric-grid watchlist-impact-metrics">
     <div><span>命中告警总数</span><strong>{{result.total.toLocaleString('en-US')}}</strong><small>当次核对的已索引告警条数</small></div>
     <div><span>核对时间</span><strong class="technical watchlist-impact-time">{{formatTime(result.checked_at)}}</strong><small>快照时刻，不随后续告警更新</small></div>
     <div><span>参与字段</span><span class="watchlist-impact-tags"><span v-for="label in fieldLabels" :key="label" class="status status-neutral">{{label}}</span></span><small>实际查询的已索引字段</small></div>
    </div></div>
    <h3 class="watchlist-impact-title">每值命中数</h3>
    <div class="table-wrap"><a-table :columns="valueColumns" :data-source="result.values" row-key="value" :pagination="false" size="small"><template #bodyCell="{column,record}">
     <span v-if="column.key==='value'" class="technical watchlist-impact-value">{{record.value}}</span>
     <span v-else-if="column.key==='count'" class="technical watchlist-impact-count">{{record.count.toLocaleString('en-US')}}</span>
    </template></a-table></div>
    <h3 class="watchlist-impact-title">告警样本</h3>
    <p v-if="!result.samples.length" class="page-description">当次核对没有可展示的样本。</p>
    <div v-else class="table-wrap"><a-table :columns="sampleColumns" :data-source="result.samples" row-key="event_id" :pagination="false" :scroll="{x:980}" size="small"><template #bodyCell="{column,record}">
     <template v-if="column.key==='observed'">{{formatTime(record['@timestamp'])}}</template>
     <ul v-else-if="column.key==='matches'" class="watchlist-impact-matches"><li v-for="match in record.matches" :key="match.field+'/'+match.value"><span class="status status-neutral">{{watchlistHitFields[match.field as keyof typeof watchlistHitFields]}}</span><span class="technical watchlist-impact-value">{{match.value}}</span></li></ul>
     <template v-else-if="column.key==='rule'"><span v-if="record.rule_name">{{record.rule_name}}</span><span v-else class="page-description">规则名称未记录</span></template>
     <span v-else-if="column.key==='severity'" class="status" :class="'status-'+record.severity">{{watchlistSeverities[record.severity as keyof typeof watchlistSeverities]}}</span>
     <template v-else-if="column.key==='sensor'"><span class="technical">{{record.sensor_id}}</span><small class="technical watchlist-impact-sub">{{record.registration_id}}</small></template>
    </template></a-table></div>
    <p class="page-description watchlist-impact-footnote">预览结果为当次核对的快照，不随后续告警更新；本次未登记任何命中，也未授予执行许可。</p>
   </template>
   <p v-else-if="!incomplete" class="page-description">点击“执行预览”核对所选修订在该窗口内的已索引告警。</p>
  </StatePanel>
 </section>
</template>
<style scoped>.watchlist-impact-form{margin-bottom:var(--section-gap);padding-top:var(--panel-inset)}.watchlist-impact-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 var(--field-gap)}.watchlist-impact-fields .ant-form-item{min-width:0}.watchlist-impact-fields .ant-input-number{width:100%}.watchlist-impact-metrics{grid-template-columns:repeat(3,minmax(0,1fr))}.watchlist-impact-metrics strong{font-size:25px;font-weight:650}.watchlist-impact-time{font-size:15px;font-weight:600}.watchlist-impact-tags{display:flex;flex-wrap:wrap;gap:var(--label-gap);margin:var(--label-gap) 0}.watchlist-impact-title{font-size:14px;margin:var(--section-gap) 0 var(--related-gap)}.watchlist-impact-value{overflow-wrap:anywhere}.watchlist-impact-count{display:block;text-align:right}.watchlist-impact-matches{list-style:none;padding:0;margin:0;display:grid;gap:var(--label-gap)}.watchlist-impact-matches>li{display:grid;gap:var(--label-gap);min-width:0}.watchlist-impact-matches .status{justify-self:start}.watchlist-impact-sub{display:block;margin-top:var(--label-gap);font-size:11px}.watchlist-impact-footnote{margin-top:var(--section-gap)}</style>
