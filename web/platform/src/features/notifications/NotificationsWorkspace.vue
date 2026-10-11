<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import {Select,message} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import {useNotifications} from './useNotifications'
import {deliveryNames,type Channel,type ChannelChange,type Delivery} from './notifications'
import ChannelTable from './ChannelTable.vue'
import ChannelForm from './ChannelForm.vue'
import DeliveryTable from './DeliveryTable.vue'
import DeliveryDetail from './DeliveryDetail.vue'
const {view,change}=useWorkspaceView(['channels','deliveries'])
const state=useNotifications(view)
const {channels,deliveries,available,development,pending,error,busy,actionError,cursors,nextCursor}=state
const editing=shallowRef<Channel|null>(null),editorOpen=shallowRef(false),selectedID=shallowRef(''),filter=shallowRef('')
const selected=computed(()=>deliveries.value.find(item=>item.id===selectedID.value)??null)
watch(view,()=>{editorOpen.value=false;editing.value=null;selectedID.value='';filter.value=''})
function edit(record:Channel|null){state.clearActionError();editing.value=record;editorOpen.value=true}
async function save(change:ChannelChange){if(await state.save(change)){editorOpen.value=false;message.success('通知渠道已保存')}}
async function test(record:Channel){if(await state.test(record)){message.success('测试投递已受理，请查看推送日志');change('deliveries')}}
async function retry(record:Delivery){if(await state.retry(record))message.success('人工重试已受理')}
</script>
<template>
  <header class="page-header"><div><h1>通知中心</h1><p class="page-description">配置告警通知和日志转发渠道，核对每次投递的处理状态与渠道回执。</p></div><div class="filter-actions"><a-button :loading="pending" @click="state.refresh">刷新</a-button><a-button v-if="view==='channels'" type="primary" :disabled="!available||busy||channels.length>=50" @click="edit(null)">创建渠道</a-button></div></header>
  <WorkspaceTabs :active="view" :items="[{key:'channels',label:'通知渠道'},{key:'deliveries',label:'推送日志'}]" label="通知中心功能" @change="change" />
  <a-alert v-if="actionError&&!editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert v-if="view==='channels'&&!pending&&!available&&!error" type="info" message="通知服务尚未启用，渠道配置暂不可用。" show-icon class="section-gap" />
  <a-form v-if="view==='deliveries'" :model="{filter}" layout="inline" class="panel delivery-filter" @finish="state.search(filter)"><a-form-item label="投递状态"><Select v-model:value="filter" :options="[{value:'',label:'全部状态'},...Object.entries(deliveryNames).map(([value,label])=>({value,label}))]" style="width:170px" /></a-form-item><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="filter='';state.search('')">重置</a-button></a-form>
  <section class="panel"><div class="panel-header"><h2>{{view==='channels'?'通知渠道':'推送日志'}}</h2><span>{{view==='channels'?channels.length+' / 50 个渠道':'当前页 '+deliveries.length+' 条'}}</span></div><StatePanel :loading="pending" :error="error" :empty="view==='channels'?channels.length===0:deliveries.length===0" :description="view==='channels'?'暂无通知渠道，可创建渠道并发送测试消息。':'当前条件下没有推送日志。'" @retry="state.refresh"><ChannelTable v-if="view==='channels'" :items="channels" :busy="busy" :available="available" @edit="edit" @test="test" /><DeliveryTable v-else :items="deliveries" @view="selectedID=$event.id" /></StatePanel><div v-if="view==='deliveries'" class="delivery-pagination"><a-button :disabled="pending||cursors.length<=1" @click="state.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!nextCursor" @click="state.next">下一页</a-button></div></section>
  <ChannelForm v-if="editorOpen" :record="editing" :pending="busy" :error="actionError" :development="development" @save="save" @close="editorOpen=false" />
  <DeliveryDetail :record="selected" :busy="busy" @close="selectedID=''" @retry="retry" />
</template>
<style scoped>.delivery-filter{display:flex;flex-wrap:wrap;align-items:center;gap:var(--related-gap);padding:var(--panel-inset)}.delivery-filter .ant-form-item{margin:0}.delivery-pagination{display:flex;justify-content:flex-end;gap:var(--related-gap);align-items:center;padding:var(--panel-inset);flex-wrap:wrap}</style>
