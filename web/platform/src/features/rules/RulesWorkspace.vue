<script setup lang="ts">
import { computed, onMounted, onScopeDispose, reactive, shallowRef } from 'vue'
import { Table as ATable, Modal as AModal, Select as ASelect, message } from 'ant-design-vue'
import type { RulePackage, Sensor } from '@starbeacon/shared/types.ts'
import { formatTime } from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import ReplayWorkspace from '@starbeacon/shared/components/ReplayWorkspace.vue'
import RuleEditor from '@starbeacon/shared/components/RuleEditor.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import {inspectRules} from '@starbeacon/shared/utils/ruleSyntax.ts'
import { session } from '../../session'
const {view,change}=useWorkspaceView(session.current.value?.role==='admin'?['packages','samples','tasks']:['packages'])
const canEdit=computed(()=>session.current.value?.role==='admin')
const views=[{key:'packages',label:'规则包'},{key:'samples',label:'重放样本'},{key:'tasks',label:'重放任务'}]
const items=shallowRef<RulePackage[]>([]),pending=shallowRef(true),error=shallowRef(''),saving=shallowRef(false),editor=shallowRef(false),editing=shallowRef(false),formError=shallowRef('')
const form=reactive({id:'',name:'',text:'',expected_revision:0})
let controller:AbortController|undefined
async function refresh(){controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value='';try{const result=await session.api.request<{items:RulePackage[]}>('/rule-packages',{signal:current.signal});if(!current.signal.aborted)items.value=result.items}catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'规则包读取失败'}finally{if(controller===current)pending.value=false}}
async function edit(id?:string){formError.value='';editing.value=!!id;if(!id){Object.assign(form,{id:'',name:'',text:'',expected_revision:0});editor.value=true;return}const target=items.value.find(item=>item.id===id);if(!target)return;saving.value=true;try{const result=await session.api.request<RulePackage>(`/rule-packages/${encodeURIComponent(id!)}/${target.revision}`);Object.assign(form,{id:result.id,name:result.name,text:result.text??'',expected_revision:result.revision});editor.value=true}catch(e){message.error(e instanceof Error?e.message:'读取失败')}finally{saving.value=false}}
async function save(){if(!canEdit.value)return;if(!form.name.trim()||!form.text.trim()){formError.value='请填写规则包名称和规则文本';return}if(new TextEncoder().encode(form.text).length>900*1024){formError.value='规则文本超过 900 KiB，请拆分受控规则包';return}const problems=inspectRules(form.text);if(problems.length){formError.value=`第 ${problems[0]!.line} 行：${problems[0]!.message}`;return}saving.value=true;formError.value='';try{await session.api.request('/rule-packages',{method:'POST',body:{...form,name:form.name.trim()}});editor.value=false;message.success('规则包已保存，请完成装载检查与样本回放');await refresh()}catch(e){formError.value=e instanceof Error?e.message:'保存失败'}finally{saving.value=false}}
const selected=shallowRef<RulePackage|null>(null),sensors=shallowRef<Sensor[]>([]),sensorID=shallowRef<string|undefined>(),checking=shallowRef(false),checkError=shallowRef(''),checkResult=shallowRef('')
const options=computed(()=>sensors.value.map(row=>({value:row.id,label:`${row.name} · ${row.status==='online'?'在线':'离线'}`,disabled:!row.active||!row.health.task_capabilities?.includes('rules.validate')})))
let taskKey:string|undefined
async function inspect(id:string){const row=items.value.find(item=>item.id===id);if(!row)return;selected.value=row;sensorID.value=undefined;taskKey=undefined;checkError.value='';checkResult.value='';sensors.value=[];checking.value=true;try{const result=await session.api.request<{items:Sensor[]}>('/sensors');sensors.value=result.items}catch(e){checkError.value=e instanceof Error?e.message:'探针读取失败'}finally{checking.value=false}}
async function check(){if(!selected.value||!sensorID.value){checkError.value='请选择已配置检测引擎的探针';return}checking.value=true;checkError.value='';taskKey??=crypto.randomUUID();try{const result=await session.api.request<{id:string}>(`/sensors/${encodeURIComponent(sensorID.value)}/tasks`,{method:'POST',body:{kind:'rules.validate',package_id:selected.value.id,revision:selected.value.revision},headers:{'Idempotency-Key':taskKey}});checkResult.value=result.id;taskKey=undefined}catch(e){checkError.value=e instanceof Error?e.message:'检查提交失败'}finally{checking.value=false}}
const columns=[{title:'规则包',key:'name',width:220},{title:'修订',dataIndex:'revision',width:90},{title:'检测引擎',dataIndex:'engine_version',width:110},{title:'包摘要',key:'hash',width:210},{title:'保存时间',key:'time',width:190},{title:'操作',key:'action',width:190}]
onMounted(refresh);onScopeDispose(()=>controller?.abort())
</script>
<template>
  <header class="page-header"><div><h1>规则管理</h1><p class="page-description">管理不可变规则包修订，核对原生装载检查、样本回放和发布条件。</p></div><a-space v-if="view==='packages'"><a-button :loading="pending" @click="refresh">刷新</a-button><a-button v-if="session.current.value?.role==='admin'" type="primary" :disabled="saving" @click="edit()">创建规则包</a-button></a-space></header>
  <WorkspaceTabs :active="view" :items="session.current.value?.role==='admin'?views:views.slice(0,1)" label="规则管理功能" @change="change" />
  <template v-if="view==='packages'">
  <a-alert type="info" show-icon message="旁路规则包支持 alert 检测规则。装载检查通过后，仍需完成样本回放与完整包验收。" class="section-gap" />
  <section class="panel"><div class="panel-header"><h2>规则包</h2><span>{{ items.length }} 个规则包</span></div>
    <StatePanel :loading="pending" :error="error" :empty="items.length===0" description="暂无规则包，请创建规则包并保存检测规则。" @retry="refresh"><div class="table-wrap"><a-table :columns="columns" :data-source="items" row-key="id" :pagination="{pageSize:10,hideOnSinglePage:true}" :scroll="{x:1110}"><template #bodyCell="{column,record}">
      <template v-if="column.key==='name'"><button class="link-button" @click="edit(record.id)">{{ record.name }}</button><small class="record-id technical">{{ record.id }}</small></template>
      <span v-else-if="column.key==='hash'" class="technical" :title="record.sha256">{{ record.sha256.slice(0,20) }}…</span>
      <template v-else-if="column.key==='time'">{{ formatTime(record.created_at) }}</template>
      <template v-else-if="column.key==='action'"><a-space><a-button type="link" :disabled="saving" @click="edit(record.id)">{{canEdit?'编辑规则':'查看规则'}}</a-button><a-button v-if="canEdit" type="link" @click="inspect(record.id)">装载检查</a-button></a-space></template>
    </template></a-table></div></StatePanel>
  </section>
  </template>
  <ReplayWorkspace v-else :api="session.api" @tasks="change('tasks')" :view="view==='tasks'?'tasks':'samples'" />
  <a-modal :title="!canEdit?'查看规则包':editing?'规则包修订':'创建规则包'" :open="editor" :width="900" :confirm-loading="saving" :footer="canEdit?undefined:null" ok-text="保存修订" :cancel-button-props="{disabled:saving}" :mask-closable="!saving" @ok="save" @cancel="editor=false">
    <a-alert v-if="formError" type="error" show-icon :message="formError" class="section-gap" />
    <a-form layout="vertical" :model="form" name="rule-package"><a-form-item label="规则包名称" name="name" required><a-input v-model:value="form.name" :maxlength="128" :disabled="saving||!canEdit" placeholder="输入规则包名称" /></a-form-item><a-form-item v-if="editing" label="当前修订"><span>修订 {{ form.expected_revision }}，保存时生成下一修订并保留原内容。</span></a-form-item><a-form-item label="规则文本" name="text" required><RuleEditor v-model="form.text" :disabled="saving" :readonly="!canEdit" /></a-form-item></a-form>
  </a-modal>
  <a-modal title="规则装载检查" :open="selected!==null" :width="640" :footer="null" :closable="!checking" :mask-closable="!checking" :keyboard="!checking" @cancel="selected=null">
    <template v-if="selected"><p class="page-description section-gap">{{ selected.name }} · 修订 {{ selected.revision }} · Suricata {{ selected.engine_version }}</p><a-alert v-if="checkError" type="error" show-icon :message="checkError" class="section-gap" /><a-alert v-if="checkResult" type="success" show-icon message="检查任务已受理" class="section-gap"><template #description>任务 <span class="technical">{{ checkResult }}</span>，<router-link to="/sensors?view=tasks">查看探针执行回执</router-link>。</template></a-alert>
      <a-form layout="vertical"><a-form-item label="目标探针" html-for="rule-target-sensor" required><a-select id="rule-target-sensor" v-model:value="sensorID" :options="options" :loading="checking" :disabled="checking" style="width:100%" placeholder="选择已配置 Suricata 8.0.7 的探针" @change="taskKey=undefined" /></a-form-item></a-form><a-button type="primary" :loading="checking" :disabled="!sensorID||!!checkResult" @click="check">提交装载检查</a-button>
    </template>
  </a-modal>
</template>
