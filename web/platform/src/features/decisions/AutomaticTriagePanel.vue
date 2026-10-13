<script setup lang="ts">
import {onScopeDispose,ref,shallowRef,watch} from 'vue'
import {useRouter} from 'vue-router'
import {Table as ATable,Tag as ATag} from 'ant-design-vue'
import {session} from '../../session'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import type {PolicyRecord} from './decisionPolicies'
import {triggerStates,triggerCodes,validAutomaticTriagePage,type AutomaticTriagePage} from './automaticTriage'
const props=defineProps<{record:PolicyRecord}>(),router=useRouter(),page=shallowRef<AutomaticTriagePage>({items:[],next_cursor:''}),pending=ref(false),error=ref(''),cursor=ref(''),history=ref<string[]>([])
const columns=[{title:'告警标识',dataIndex:'event_id',width:260},{title:'状态',key:'state',width:150},{title:'核对结果',key:'code',width:260},{title:'登记时间',key:'created',width:180},{title:'操作',key:'actions',width:130}]
let read:AbortController|undefined,stopped=false
async function load(){
 if(stopped)return
 read?.abort();const c=new AbortController();read=c;pending.value=true;error.value='';page.value={items:[],next_cursor:''}
 const p=props.record,u=session.current.value,before=cursor.value
 try{
  if(!u||u.role!=='admin'||u.id!==p.created_by||u.tenant_id!==p.tenant_id)throw new Error('当前账号没有该策略自动研判记录的查看权限。')
  const result=await session.api.request<unknown>(`/decision-policies/${encodeURIComponent(p.id)}/revisions/${p.revision}/triggers${before?'?before='+encodeURIComponent(before):''}`,{signal:c.signal})
  if(c.signal.aborted)return
  if(!validAutomaticTriagePage(result,p,before))throw new Error('自动研判记录与所选策略、探针或修订不一致，请重试。')
  if(!c.signal.aborted)page.value=result
 }catch(e){if(!c.signal.aborted)error.value=e instanceof Error?e.message:'自动研判记录读取失败。'}finally{if(read===c)pending.value=false}
}
function next(){if(pending.value||!page.value.next_cursor)return;history.value.push(cursor.value);cursor.value=page.value.next_cursor;void load()}
function previous(){if(pending.value||!history.value.length)return;cursor.value=history.value.pop()!;void load()}
function refresh(){cursor.value='';history.value=[];void load()}
watch(()=>[props.record.id,props.record.revision,props.record.definition_sha256,session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role],refresh,{immediate:true})
onScopeDispose(()=>{stopped=true;read?.abort()})
</script>
<template>
 <div class="trigger-heading"><p class="page-description">{{record.name}} · 修订 {{record.revision}}。登记和提交状态不代表模型研判或设备处置已完成。</p><a-button :loading="pending" @click="refresh">刷新记录</a-button></div>
 <StatePanel :loading="pending" :error="error" :empty="!page.items.length" description="本策略修订暂无自动研判登记。仅处理启用许可后的指定探针与告警等级，每日登记量受配置额度限制。" @retry="load">
  <a-table :data-source="page.items" :columns="columns" row-key="id" :pagination="false" size="small" :scroll="{x:980}"><template #bodyCell="{column,record:row}">
   <template v-if="column.dataIndex==='event_id'"><span class="technical trigger-id">{{row.event_id}}</span></template>
   <template v-else-if="column.key==='state'"><a-tag :color="row.state==='submitted'?'green':row.state==='skipped'?'orange':'blue'">{{triggerStates[row.state as keyof typeof triggerStates]}}</a-tag></template>
   <template v-else-if="column.key==='code'">{{triggerCodes[row.code as keyof typeof triggerCodes]}}</template>
   <template v-else-if="column.key==='created'">{{formatTime(row.created_at)}}</template>
   <template v-else-if="column.key==='actions'"><a-button v-if="row.triage_id" type="link" size="small" @click="router.push({path:'/models',query:{view:'evaluations',triage_id:row.triage_id}})">查看决策记录</a-button><span v-else>尚无研判作业</span></template>
  </template></a-table>
 </StatePanel>
 <div class="trigger-pagination"><span>当前页 {{page.items.length}} 条</span><div><a-button :disabled="pending||!history.length" @click="previous">上一页</a-button><a-button :disabled="pending||!page.next_cursor" @click="next">下一页</a-button></div></div>
</template>
<style scoped>.trigger-heading,.trigger-pagination{display:flex;align-items:center;justify-content:space-between;gap:8px}.trigger-pagination{margin-top:12px}.trigger-pagination>div{display:flex;gap:8px}.trigger-heading p{margin:0 0 8px;overflow-wrap:anywhere}.trigger-id{overflow-wrap:anywhere}@media(max-width:700px){.trigger-heading{align-items:flex-start;flex-wrap:wrap}}</style>
