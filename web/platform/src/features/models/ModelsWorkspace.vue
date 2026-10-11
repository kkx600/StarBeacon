<script setup lang="ts">
import {computed,shallowRef} from 'vue'
import {Table,Popconfirm,message} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {useModels} from './useModels'
import {providerNames,checkNames,checkClass,type ModelProvider,type ModelChange} from './models'
import ProviderForm from './ProviderForm.vue'
import CheckDetail from './CheckDetail.vue'
const state=useModels()
const {items,available,pending,error,busy,actionError}=state
const editing=shallowRef<ModelProvider|null>(null),editorOpen=shallowRef(false),selectedID=shallowRef('')
const selected=computed(()=>items.value.find(item=>item.id===selectedID.value)??null)
const columns=[{title:'提供方',key:'name',width:180},{title:'生成协议',key:'kind',width:170},{title:'模型标识',dataIndex:'model',width:220},{title:'状态',key:'enabled',width:90},{title:'公网连接',key:'external',width:100},{title:'连接验证',key:'check',width:140},{title:'操作',key:'actions',width:230,fixed:'right' as const}]
function edit(record:ModelProvider|null){state.clearActionError();editing.value=record;editorOpen.value=true}
async function save(change:ModelChange){if(await state.save(change)){editorOpen.value=false;message.success('模型配置已保存')}}
async function test(record:ModelProvider){const result=await state.test(record);if(result){selectedID.value=record.id;if(result.state==='succeeded')message.success('模型连接验证通过')}}
</script>
<template>
  <header class="page-header"><div><h1>模型配置</h1><p class="page-description">管理生成接口、连接范围和调用预算，核对模型连接验证结果。</p></div><div class="filter-actions"><a-button :loading="pending" @click="state.refresh">刷新</a-button><a-button type="primary" :disabled="pending||!available||busy||items.length>=50" @click="edit(null)">创建提供方</a-button></div></header>
  <a-alert v-if="actionError&&!editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert v-if="!pending&&!available&&!error" type="info" message="模型凭据服务尚未启用，配置暂不可用。" show-icon class="section-gap" />
  <section class="panel"><div class="panel-header"><h2>模型提供方</h2><span>{{items.length}} / 50 个提供方</span></div><StatePanel :loading="pending" :error="error" :empty="items.length===0" description="暂无模型提供方，可创建配置并验证生成接口连接。" @retry="state.refresh"><div class="table-wrap"><Table :columns="columns" :data-source="[...items]" row-key="id" :pagination="false" :scroll="{x:1130}"><template #bodyCell="{column,record}">
    <template v-if="column.key==='name'">{{record.name}}<small class="record-id">修订 {{record.revision}}</small></template><template v-else-if="column.key==='kind'">{{providerNames[record.kind as keyof typeof providerNames]}}</template><template v-else-if="column.key==='enabled'"><span :class="['status',record.enabled?'status-online':'status-disabled']">{{record.enabled?'启用':'停用'}}</span></template><template v-else-if="column.key==='external'">{{record.allow_external?'允许':'禁止'}}</template><template v-else-if="column.key==='check'"><span v-if="record.check&&record.check.provider_revision===record.revision" :class="['status',checkClass(record.check.state)]">{{checkNames[record.check.state]??'其他处理状态'}}</span><span v-else class="muted">尚未验证</span></template><template v-else-if="column.key==='actions'"><div class="filter-actions"><a-button type="link" size="small" :disabled="busy||!available" @click="edit(record as ModelProvider)">配置</a-button><Popconfirm title="验证该模型的生成接口连接？" description="将发送固定短文本，提供方可能按调用计费。" ok-text="开始验证" cancel-text="取消" :disabled="busy||!available||!record.enabled" @confirm="test(record as ModelProvider)"><a-button type="link" size="small" :disabled="busy||!available||!record.enabled">连接验证</a-button></Popconfirm><a-button type="link" size="small" @click="selectedID=record.id">结果</a-button></div></template>
  </template></Table></div></StatePanel></section>
  <ProviderForm v-if="editorOpen" :record="editing" :pending="busy" :error="actionError" @save="save" @close="editorOpen=false" />
  <CheckDetail :record="selected" @close="selectedID=''" />
</template>
