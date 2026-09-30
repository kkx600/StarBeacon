<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import {message,Modal} from 'ant-design-vue'
import {useRouter} from 'vue-router'
import {PlusOutlined,SearchOutlined,ReloadOutlined,DownloadOutlined,SettingOutlined,FilterOutlined} from '@ant-design/icons-vue'
import type {BusinessRecord,PageSpec,PreviewState} from '../models'
import {metricsFor} from '../data/fixtures'
import {formatCell} from '../composables/formatRecord'
import {useRecords,exportCsv,exportJson} from '../composables/useRecords'
import MetricBar from './MetricBar.vue'
import PageHeader from './PageHeader.vue'
import StatusTag from './StatusTag.vue'
import StatePanel from './StatePanel.vue'
import RecordDetail from './RecordDetail.vue'
import RecordForm from './RecordForm.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>()
const {records,save,updateStatus}=useRecords(props.page)
const router=useRouter()
const query=ref('');const filterStatus=ref<string>();const scope=ref('全部网络域');const selectedKeys=ref<string[]>([]);const currentPage=ref(1);const pageSize=ref(8)
const detailOpen=ref(false);const formOpen=ref(false);const selected=ref<BusinessRecord>();const editing=ref<BusinessRecord>();const activeQuery=ref('');const advanced=ref(false);const protocol=ref<string>();const method=ref<string>();const source=ref('');const destination=ref('');const path=ref('');const timeWindow=ref('最近 24 小时')
const batchIds=ref<string[]>([])
const formPage=computed<PageSpec>(()=>batchIds.value.length?{...props.page,primary:`${props.page.family==='alert'?'批量研判':'批量处理'} · ${batchIds.value.length} 项`,fields:[{key:'owner',label:'分派给',type:'select',required:true,value:'值班分析组',options:['值班分析组','陈宁','林悦']},{key:'status',label:'处理状态',type:'select',required:true,value:props.page.statusOptions?.[0]??'待验证',options:props.page.statusOptions??['待验证']},{key:'reason',label:'处理依据',type:'textarea',required:true}]}:props.page)
const visibleCols=ref(props.page.columns.map(c=>c.key))
const statusOptions=computed(()=>[...new Set(records.value.map(r=>r.status))].map(value=>({value,label:value})))
const filtered=computed(()=>props.state==='empty'?[]:records.value.filter(r=>(!activeQuery.value||[r.id,...props.page.columns.map(c=>r[c.key])].some(v=>String(v??'').toLowerCase().includes(activeQuery.value.toLowerCase())))&&(!filterStatus.value||r.status===filterStatus.value)&&(scope.value==='全部网络域'||r.scope===scope.value)&&(!protocol.value||r.protocol===protocol.value)&&(!method.value||r.method===method.value)&&(!source.value||String(r.source).includes(source.value))&&(!destination.value||String(r.destination).includes(destination.value))&&(!path.value||String(r.path).includes(path.value))&&(timeWindow.value!=='最近 1 小时'||String(r.time)>='2026-09-30 08:45:00')))
const columns=computed(()=>[...props.page.columns.filter(c=>visibleCols.value.includes(c.key)).map(c=>({...c,dataIndex:c.key,ellipsis:c.key!=='status'&&c.key!=='name',sorter:(a:BusinessRecord,b:BusinessRecord)=>String(a[c.key]??'').localeCompare(String(b[c.key]??''),'zh-CN',{numeric:true})})),{title:'操作',key:'actions',width:120,fixed:'right' as const}])
const metrics=computed(()=>metricsFor(props.page,props.state==='empty'))
watch(()=>props.state,state=>{detailOpen.value=state==='detail';formOpen.value=state==='action';if(state==='detail')selected.value=records.value[0];if(state==='action'){editing.value=undefined;batchIds.value=props.page.family==='alert'?records.value.map(r=>r.id):[]}},{immediate:true})
function search(){activeQuery.value=query.value.trim();currentPage.value=1;selectedKeys.value=[]}
function reset(){query.value='';activeQuery.value='';filterStatus.value=undefined;scope.value='全部网络域';protocol.value=undefined;method.value=undefined;source.value='';destination.value='';path.value='';timeWindow.value='最近 24 小时';currentPage.value=1;selectedKeys.value=[]}
function view(record:BusinessRecord){selected.value=record;detailOpen.value=true}
function create(){batchIds.value=props.page.family==='alert'?(selectedKeys.value.length?[...selectedKeys.value]:filtered.value.map(r=>r.id)):[];editing.value=undefined;formOpen.value=true}
function operate(record:BusinessRecord){
  batchIds.value=[]
  if(props.page.readOnly){exportJson(record.id,record);return}
  if(props.page.family==='action'){
    Modal.confirm({title:'撤销响应租约',content:`目标：${record.target}。本原型将更新本地租约状态；生产撤销需要执行采集器回执与设备配置核验。`,okText:'确认撤销',cancelText:'取消',onOk:()=>{updateStatus([record.id],'撤销待核验');message.success('本地示例租约已进入撤销待核验状态。')}});return
  }
  editing.value=record;formOpen.value=true
}
function close(){detailOpen.value=false;formOpen.value=false;batchIds.value=[];if(props.state==='detail'||props.state==='action')emit('state','data')}
function submit(values:Record<string,unknown>){if(props.page.actionMode==='export'){if(values.format==='JSON')exportJson(props.page.id,filtered.value);else exportCsv(props.page,filtered.value)}else if(batchIds.value.length){batchIds.value.forEach(id=>save(values,id))}else save(values,editing.value?.id);formOpen.value=false;selectedKeys.value=[];batchIds.value=[];if(props.state!=='data')emit('state','data');message.success(props.page.actionMode==='export'?'示例数据已导出。':'已保存在本地原型中。')}
function batch(){if(!selectedKeys.value.length)return;batchIds.value=[...selectedKeys.value];editing.value=undefined;formOpen.value=true}
</script>
<template>
  <PageHeader :title="page.title" :description="page.description"><a-space><a-button @click="exportCsv(page,filtered)"><DownloadOutlined/> 导出</a-button><a-button v-if="page.kind==='table'&&page.family!=='audit'&&page.family!=='login-log'" type="primary" @click="create"><PlusOutlined v-if="!page.readOnly"/>{{page.primary}}</a-button></a-space></PageHeader>
  <MetricBar :items="metrics"/>
  <a-alert v-if="page.notice" :message="page.notice" :type="['action','inspection','integrity','tls','decision'].includes(page.family)?'warning':'info'" show-icon class="page-notice"/>
  <slot name="before"/>
  <section class="panel filter-panel" aria-label="检索条件">
    <div class="filter-grid"><label><span>关键词</span><a-input v-model:value="query" :placeholder="`名称、编号或${page.columns[1]?.title??'字段'}`" allow-clear @press-enter="search"/></label><label><span>状态</span><a-select v-model:value="filterStatus" placeholder="全部状态" allow-clear :options="statusOptions"/></label><label><span>网络域</span><a-select v-model:value="scope" :options="['全部网络域','总部网络域','研发网络域','分支网络域'].map(value=>({value,label:value}))"/></label><div class="filter-buttons"><a-button type="primary" @click="search"><SearchOutlined/>查询</a-button><a-button @click="reset">重置</a-button><a-button v-if="['alert','session','log','behavior'].includes(page.family)" type="link" @click="advanced=!advanced">{{advanced?'收起':'高级筛选'}}<FilterOutlined/></a-button></div></div>
    <div v-if="advanced" class="filter-grid advanced-filters"><label><span>源 IP</span><a-input v-model:value="source" placeholder="例如 198.51.100.24"/></label><label><span>目的 IP</span><a-input v-model:value="destination" placeholder="例如 10.20.1.15"/></label><label><span>协议</span><a-select v-model:value="protocol" placeholder="全部协议" allow-clear :options="['HTTP','TLS','DNS','TCP','UDP','SMB'].map(value=>({value,label:value}))"/></label><label><span>请求方法</span><a-select v-model:value="method" placeholder="全部方法" allow-clear :options="['GET','POST','PUT','DELETE','HEAD','OPTIONS'].map(value=>({value,label:value}))"/></label><label><span>Path 路径</span><a-input v-model:value="path" placeholder="例如 /admin/login"/></label><label><span>时间范围</span><a-select v-model:value="timeWindow" :options="['最近 1 小时','最近 24 小时','最近 7 天'].map(value=>({value,label:value}))"/></label></div>
  </section>
  <section class="panel table-panel">
    <div class="table-toolbar"><div><h2>{{page.objectLabel}}记录</h2><span class="muted">{{filtered.length}} 条记录</span><a-tag v-if="selectedKeys.length" color="blue">已选 {{selectedKeys.length}} 项</a-tag></div><a-space><a-button v-if="!page.readOnly" size="small" :disabled="!selectedKeys.length" @click="batch">批量{{page.family==='alert'?'分派':'操作'}}</a-button><a-tooltip title="刷新记录"><a-button size="small" aria-label="刷新记录" @click="emit('state','data')"><ReloadOutlined/></a-button></a-tooltip><a-popover trigger="click" title="显示字段" placement="bottomRight"><template #content><a-checkbox-group v-model:value="visibleCols" class="column-selector" :options="page.columns.map(c=>({label:c.title,value:c.key}))"/></template><a-button size="small" aria-label="设置表格字段"><SettingOutlined/></a-button></a-popover></a-space></div>
    <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
    <StatePanel v-else-if="!filtered.length" state="empty" :title="page.emptyTitle" :description="activeQuery||filterStatus?'没有匹配当前条件的记录。请调整筛选或清除条件。':page.emptyDescription" :action="activeQuery||filterStatus?'清除筛选':page.family==='alert'?'查看数据源':page.readOnly?'重新加载':page.primary" @action="activeQuery||filterStatus?reset():page.family==='alert'?router.push('/page/data-sources'):page.readOnly?emit('state','data'):create()"/>
    <a-table v-else :columns="columns" :data-source="filtered" row-key="id" size="middle" :scroll="{x:Math.max(1000,columns.reduce((sum,c)=>sum+(c.width??140),0))}" :pagination="{current:currentPage,pageSize,total:filtered.length,showSizeChanger:true,pageSizeOptions:['8','16','32'],showTotal:(total:number)=>`共 ${total} 条`}" :row-selection="{selectedRowKeys:selectedKeys,onChange:(keys:unknown[])=>selectedKeys=keys.map(String)}" @change="(pagination:{current?:number;pageSize?:number})=>{currentPage=pagination.current??1;pageSize=pagination.pageSize??8}">
      <template #bodyCell="{column,record,text}"><template v-if="column.key==='name'"><button class="record-link" @click="view(record)">{{text}}</button><small class="row-id">{{record.id}}</small></template><StatusTag v-else-if="column.kind==='status'||column.kind==='level'" :value="text"/><template v-else-if="column.kind==='progress'"><a-progress :percent="Number(text)" size="small" :stroke-color="'#2563eb'"/></template><span v-else-if="column.kind==='percent'" class="tabular">{{formatCell(text,column)}}</span><span v-else-if="column.key==='actions'" class="row-actions"><a-button type="link" size="small" @click="view(record)">查看</a-button><a-button type="link" size="small" @click="operate(record)">{{page.rowAction}}</a-button></span><span v-else :class="{mono:column.kind==='code',muted:text===null||text===undefined}">{{text??'未提供'}}</span></template>
    </a-table>
  </section>
  <RecordDetail :open="detailOpen" :page="page" :record="selected" @close="close" @action="detailOpen=false;operate(selected!)"/>
  <RecordForm :open="formOpen" :page="formPage" :record="editing" @close="close" @save="submit"/>
</template>
