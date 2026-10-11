<script setup lang="ts">
import {reactive,shallowRef,toRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import type {AuditRecord} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import AuditTable from './AuditTable.vue'
import AuditDetail from './AuditDetail.vue'
import {actionNames} from './audits'
import {useAudits,type AuditCategory} from './useAudits'
const props=defineProps<{category:AuditCategory}>()
const {result,pending,error,cursors,search,refresh,next,previous}=useAudits(toRef(props,'category'))
const defaults={username:'',action:'',success:'',hours:168},form=reactive({...defaults}),selected=shallowRef<AuditRecord|null>(null)
watch(()=>props.category,()=>{Object.assign(form,defaults);selected.value=null})
const actions=[{label:'全部操作',value:''},...Object.entries(actionNames).filter(([value])=>value!=='auth.password_verification').map(([value,label])=>({label,value}))]
</script>
<template>
  <a-form :model="form" class="panel filter-form" layout="vertical" @finish="search({...form})"><a-form-item label="账号"><a-input v-model:value="form.username" :maxlength="64" placeholder="完整账号名称" allow-clear/></a-form-item><a-form-item v-if="category==='operations'" label="操作类型"><a-select v-model:value="form.action" :options="actions"/></a-form-item><a-form-item v-else label="凭据验证结果"><a-select v-model:value="form.success" :options="[{label:'全部结果',value:''},{label:'验证通过',value:'true'},{label:'验证失败',value:'false'}]"/></a-form-item><a-form-item label="时间范围"><a-select v-model:value="form.hours" :options="[{label:'最近 24 小时',value:24},{label:'最近 7 天',value:168},{label:'最近 30 天',value:720}]"/></a-form-item><div class="filter-actions"><a-button html-type="submit" type="primary" :loading="pending">查询</a-button><a-button :disabled="pending" @click="Object.assign(form,defaults);search({...form})">重置</a-button><a-button :disabled="pending" @click="refresh">刷新</a-button></div></a-form>
  <section class="panel"><div class="panel-header"><h2>{{category==='operations'?'操作日志':'登录日志'}}</h2><span>当前页 {{result.items.length}} 条</span></div><StatePanel :loading="pending" :error="error" :empty="result.items.length===0" description="当前条件下没有审计日志。" @retry="refresh"><AuditTable :category="category" :records="result.items" @view="selected=$event"/></StatePanel><div class="audit-pagination"><a-button :disabled="pending||cursors.length<=1" @click="previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!result.next_cursor" @click="next">下一页</a-button></div></section>
  <AuditDetail :record="selected" @close="selected=null"/>
</template>
<style scoped>.audit-pagination {display:flex;justify-content:flex-end;align-items:center;gap:var(--related-gap);padding:var(--panel-inset);flex-wrap:wrap}</style>
