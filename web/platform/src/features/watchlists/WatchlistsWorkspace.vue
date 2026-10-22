<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import WatchlistTable from '@starbeacon/shared/components/WatchlistTable.vue'
import WatchlistForm from '@starbeacon/shared/components/WatchlistForm.vue'
import WatchlistDetail from '@starbeacon/shared/components/WatchlistDetail.vue'
import WatchlistPreview from '@starbeacon/shared/components/WatchlistPreview.vue'
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {readWatchlist,watchlistDefinitionShape,watchlistKinds,type WatchlistChange,type WatchlistRecord} from '@starbeacon/shared/watchlists.ts'
import {session} from '../../session'
import {useWatchlists} from './useWatchlists'
import {useWatchlistPreview} from './useWatchlistPreview'
import {useWatchlistSensors} from './useWatchlistSensors'

const model=useWatchlists(),preview=useWatchlistPreview(),sensors=useWatchlistSensors(),message=useFeedback(),canEdit=computed(()=>session.current.value?.role==='admin')
const filters=reactive({keyword:'',active:'',kind:''}),editing=shallowRef(false),editRecord=shallowRef<WatchlistRecord|null>(null),editDraft=shallowRef<WatchlistChange|undefined>()
const detailTarget=shallowRef<WatchlistRecord|null>(null),detail=shallowRef<WatchlistRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef(''),revision=shallowRef(1),previewRecord=shallowRef<WatchlistRecord|null>(null),clock=shallowRef(Date.now())
let detailController:AbortController|undefined,stopped=false
const timer=setInterval(()=>{clock.value=Date.now()},30000)
function closeDetail(){detailController?.abort();detailController=undefined;detailTarget.value=null;detail.value=null;detailPending.value=false;detailError.value=''}
function closePreview(){preview.clear();previewRecord.value=null}
function closeReadOverlays(){closeDetail();closePreview()}
function edit(record:WatchlistRecord|null,flip=false){
 if(!canEdit.value||model.busy.value)return
 closeReadOverlays();editRecord.value=record;editDraft.value=undefined
 if(record&&flip)editDraft.value={id:record.id,expected_revision:record.revision,name:record.name,description:record.description,active:!record.active,definition:watchlistDefinitionShape(record.definition)}
 model.clearError();editing.value=true;void sensors.refresh()
}
function closeForm(){if(model.busy.value)return;editing.value=false;editRecord.value=null;editDraft.value=undefined;preview.clear()}
async function save(input:WatchlistChange){if(await model.save(input)){closeForm();message.success('名单配置已保存');void model.refresh()}}
async function confirm(){if(await model.confirm()){closeForm();message.success('原提交结果已确认');void model.refresh()}}
function inspect(record:WatchlistRecord){if(model.busy.value||model.unconfirmed.value)return;closePreview();detailTarget.value=record;void read(record.revision)}
async function read(value:number){
 const target=detailTarget.value
 if(stopped||!target||!Number.isSafeInteger(value)||value<1||value>target.revision)return
 detailController?.abort();const controller=new AbortController();detailController=controller;detailPending.value=true;detailError.value='';detail.value=null;revision.value=value
 const tenant=session.current.value?.tenant_id??'',timeout=setTimeout(()=>controller.abort(),30000)
 try{const result=await session.api.request<unknown>(`/watchlists/${encodeURIComponent(target.id)}/revisions/${value}`,{signal:controller.signal});if(detailController!==controller||stopped)return;if(controller.signal.aborted)throw new Error('修订读取超时，请重试。');const checked=await readWatchlist(result,tenant);if(checked.id!==target.id||checked.revision!==value)throw new Error('名单修订与所选记录不一致，请刷新后核对。');if(detailController!==controller||stopped)return;if(controller.signal.aborted)throw new Error('修订读取超时，请重试。');detail.value=checked}
 catch(cause){if(!stopped&&detailController===controller)detailError.value=controller.signal.aborted?'修订读取超时，请重试。':cause instanceof Error?cause.message:'名单修订读取失败。'}finally{clearTimeout(timeout);if(detailController===controller)detailPending.value=false}
}
function test(record:WatchlistRecord){if(!canEdit.value||model.busy.value||model.unconfirmed.value)return;closeReadOverlays();previewRecord.value=record;void preview.run({definition:watchlistDefinitionShape(record.definition),active:record.active,targets:[]})}
function search(){closeReadOverlays();model.search(filters.keyword,filters.active,filters.kind)}
function reset(){filters.keyword='';filters.active='';filters.kind='';search()}
function refresh(){closeReadOverlays();void model.refresh()}
function page(direction:'next'|'previous'){closeReadOverlays();model[direction]()}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),()=>{closeReadOverlays();editing.value=false;editRecord.value=null;editDraft.value=undefined;filters.keyword='';filters.active='';filters.kind=''},{flush:'sync'})
onScopeDispose(()=>{stopped=true;clearInterval(timer);detailController?.abort()})
</script>
<template>
 <header class="page-header"><div><h1>保护与观察名单</h1><p class="page-description">按指定探针、匹配值和有效期维护保护或观察范围，保留每次配置依据。</p></div><a-button :loading="model.pending.value" :disabled="model.busy.value" @click="refresh">刷新目录</a-button></header>
 <a-alert :type="model.unconfirmed.value?'warning':'info'" show-icon :message="model.unconfirmed.value?'上次名单提交结果尚未确认。请点击“核对原提交”完成核对后，再查看或维护其他名单。':'名单不删除原始告警。保护范围与观察命中分别保留，任何设备动作仍须核对当前授权、注册身份和有效期。'" class="section-gap"/>
 <form class="watchlists-toolbar panel panel-body" @submit.prevent="search"><a-input v-model:value="filters.keyword" aria-label="筛选名单名称" :maxlength="128" placeholder="名单名称" allow-clear/><a-select v-model:value="filters.kind" aria-label="筛选名单类型" :options="[{value:'',label:'全部类型'},...Object.entries(watchlistKinds).map(([value,label])=>({value,label}))]"/><a-select v-model:value="filters.active" aria-label="筛选名单配置状态" :options="[{value:'',label:'全部配置状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]"/><a-button type="primary" html-type="submit" :loading="model.pending.value">查询</a-button><a-button :disabled="model.pending.value" @click="reset">重置</a-button><a-button v-if="canEdit" :disabled="model.busy.value" @click="edit(null)">{{model.unconfirmed.value?'核对原提交':'创建名单'}}</a-button></form>
 <section class="panel"><div class="panel-header"><h2>名单目录</h2><span>当前 {{model.page.value.items.length}} 项</span></div><div v-if="model.error.value&&model.page.value.items.length" class="panel-body"><a-alert type="warning" show-icon message="名单更新失败，当前保留上次读取结果" :description="model.error.value"/></div><StatePanel :loading="model.pending.value&&!model.page.value.items.length" :error="model.page.value.items.length?undefined:model.error.value" :empty="!model.page.value.items.length" description="当前条件下没有名单。管理员可创建指定探针范围的名单，并设置业务期限与配置依据。" @retry="model.refresh"><WatchlistTable :items="model.page.value.items" :can-edit="canEdit" :disabled="model.busy.value||model.unconfirmed.value||!!model.error.value" :now="clock" @inspect="inspect" @edit="edit" @preview="test" @state="edit($event,true)"/></StatePanel><div class="watchlists-pagination"><span class="page-description">状态按所读修订与当前时间计算；历史默认保留 180 天，业务有效期独立。最多 256 项名单。</span><a-button :disabled="model.pending.value||model.cursors.value.length<=1" @click="page('previous')">上一页</a-button><span>第 {{model.cursors.value.length}} 页</span><a-button :disabled="model.pending.value||!!model.error.value||!model.page.value.next_cursor" @click="page('next')">下一页</a-button></div></section>
 <WatchlistForm v-if="editing" :record="editRecord" :draft="model.draft()??editDraft" :busy="model.busy.value" :unconfirmed="model.unconfirmed.value" :error="model.mutationError.value" :sensors="sensors.items.value" :sensors-pending="sensors.pending.value" :sensors-error="sensors.error.value" :preview="preview.result.value" :preview-pending="preview.pending.value" :preview-error="preview.error.value" @save="save" @confirm="confirm" @close="closeForm" @preview="preview.run" @change="preview.clear" @refresh-sensors="sensors.refresh"/>
 <WatchlistDetail v-else-if="detailTarget" :record="detail" :pending="detailPending" :error="detailError" :revision="revision" :maximum="detailTarget.revision" @read="read" @close="closeDetail"/>
 <WatchlistPreview v-else-if="previewRecord" :record="previewRecord" :result="preview.result.value" :input="preview.input.value" :pending="preview.pending.value" :error="preview.error.value" @run="preview.run" @change="preview.clear" @close="closePreview"/>
</template>
<style scoped>.watchlists-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}.watchlists-toolbar>.ant-input-affix-wrapper{width:240px}.watchlists-toolbar>.ant-select{width:150px}.watchlists-pagination{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap;padding:12px}.watchlists-pagination>.page-description{flex:1;min-width:200px}</style>
