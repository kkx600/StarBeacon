<script setup lang="ts">
import {computed,onScopeDispose,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {Select as ASelect} from 'ant-design-vue'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
import WatchlistTable from '../../../web/packages/shared/src/components/WatchlistTable.vue'
import WatchlistForm from '../../../web/packages/shared/src/components/WatchlistForm.vue'
import WatchlistDetail from '../../../web/packages/shared/src/components/WatchlistDetail.vue'
import WatchlistPreview from '../../../web/packages/shared/src/components/WatchlistPreview.vue'
import {readWatchlistReceipt,watchlistChangeError,watchlistDefinitionShape,watchlistKinds,type WatchlistChange,type WatchlistRecord,type WatchlistPreviewRequest,type WatchlistPreviewResult} from '../../../web/packages/shared/src/watchlists'
import {goJSONDigest} from '../../../web/packages/shared/src/utils/goJSONDigest'
import {watchlistExamples,watchlistExampleClock,watchlistExampleTime,watchlistExampleSensors,previewWatchlistExample} from '../data/watchlists'

const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[state:PreviewState]}>(),route=useRoute(),router=useRouter()
const records=shallowRef<WatchlistRecord[]>([]),ready=shallowRef(false),sourceError=shallowRef(''),keyword=shallowRef(''),applied=shallowRef(''),kind=shallowRef(''),active=shallowRef(''),appliedKind=shallowRef(''),appliedActive=shallowRef('')
const overlay=shallowRef<''|'form'|'detail'|'preview'>(''),selected=shallowRef<WatchlistRecord|null>(null),formRecord=shallowRef<WatchlistRecord|null>(null),draft=shallowRef<WatchlistChange>(),detail=shallowRef<WatchlistRecord|null>(null),revision=shallowRef(1)
const error=shallowRef(''),busy=shallowRef(false),unconfirmed=shallowRef(false),preview=shallowRef<WatchlistPreviewResult|null>(null),previewInput=shallowRef<WatchlistPreviewRequest|null>(null),previewPending=shallowRef(false),previewError=shallowRef('')
const versions=new Map<string,WatchlistRecord[]>()
let generation=0,attempt:WatchlistChange|undefined,receipt:WatchlistRecord|undefined,disposed=false
const filtered=computed(()=>props.state==='empty'?[]:records.value.filter(row=>(!applied.value||row.name.toLowerCase().includes(applied.value.toLowerCase()))&&(!appliedKind.value||row.definition.kind===appliedKind.value)&&(!appliedActive.value||String(row.active)===appliedActive.value)))
const forbidden=computed(()=>route.query.list_state==='forbidden')
const maximum=computed(()=>records.value.find(row=>row.id===selected.value?.id)?.revision??1)
const loading=computed(()=>!ready.value||props.state==='loading')
const pageError=computed(()=>sourceError.value||(forbidden.value?'当前示例无权读取名单，请切换授权示例身份后重试。':props.state==='error'?'合成名单目录暂时不可用，请重试。':''))
function clearPreview(){generation++;preview.value=null;previewInput.value=null;previewPending.value=false;previewError.value=''}
function resetAction(){clearPreview();error.value='';unconfirmed.value=false;attempt=undefined;receipt=undefined;draft.value=undefined}
function close(){if(busy.value)return;overlay.value='';clearPreview();formRecord.value=null;draft.value=undefined;if(!unconfirmed.value)resetAction();if(props.state==='action'||props.state==='detail'||route.query.panel)void router.replace({query:{...route.query,state:'data',panel:undefined,list_state:undefined},hash:route.hash})}
function resume(){if(!attempt||!unconfirmed.value||busy.value)return;clearPreview();formRecord.value=null;selected.value=records.value.find(row=>row.id===attempt!.id)??null;draft.value=structuredClone(attempt);overlay.value='form'}
function create(){if(unconfirmed.value){resume();return}resetAction();selected.value=null;formRecord.value=null;overlay.value='form'}
function search(){applied.value=keyword.value.trim();appliedKind.value=kind.value;appliedActive.value=active.value;if(overlay.value!=='form')overlay.value=''}
function resetFilters(){keyword.value='';kind.value='';active.value='';search()}
function edit(record:WatchlistRecord,toggle=false){resetAction();selected.value=record;formRecord.value=record;if(toggle)draft.value={id:record.id,expected_revision:record.revision,name:record.name,description:record.description,active:!record.active,definition:watchlistDefinitionShape(record.definition)};overlay.value='form'}
function inspect(record:WatchlistRecord){resetAction();selected.value=record;detail.value=record;revision.value=record.revision;overlay.value='detail'}
function read(value:number){const row=versions.get(selected.value?.id??'')?.find(item=>item.revision===value);if(row){detail.value=row;revision.value=value}}
function inspectPreview(record:WatchlistRecord){resetAction();selected.value=record;overlay.value='preview';void runPreview({definition:watchlistDefinitionShape(record.definition),active:record.active,targets:[]})}
async function runPreview(input:WatchlistPreviewRequest){
 const current=++generation;previewPending.value=true;previewError.value='';preview.value=null;previewInput.value=structuredClone(input)
 try{const result=await previewWatchlistExample(input);if(current===generation&&!disposed)preview.value=result}catch(e){if(current===generation&&!disposed)previewError.value=e instanceof Error?e.message:'合成核验未完成'}finally{if(current===generation&&!disposed)previewPending.value=false}
}
async function record(input:WatchlistChange){
 const invalid=watchlistChangeError(input);if(invalid)throw new Error(invalid)
 const current=records.value.find(row=>row.id===input.id)
 if((current?.revision??0)!==input.expected_revision)throw new Error('名单修订已变化，请关闭表单并读取当前修订。')
 const now=new Date().toISOString(),expires=new Date(Date.now()+180*86400000).toISOString()
 const result=await readWatchlistReceipt({tenant_id:'tenant_example',id:input.id,revision:input.expected_revision+1,name:input.name,description:input.description,active:input.active,definition:watchlistDefinitionShape(input.definition),definition_sha256:await goJSONDigest(watchlistDefinitionShape(input.definition)),created_by:'admin_example',created_at:now,expires_at:expires},'tenant_example',input,'admin_example')
 records.value=[result,...records.value.filter(row=>row.id!==result.id)];versions.set(result.id,[result,...versions.get(result.id)??[]]);return result
}
async function save(input:WatchlistChange){
 if(busy.value||unconfirmed.value||forbidden.value)return
 busy.value=true;error.value=''
 try{
  if(route.query.list_state==='conflict')throw new Error('合成修订冲突示例：名单已被其他管理员保存，请关闭表单并刷新。')
  const result=await record(input)
  if(route.query.list_state==='unknown'){attempt=structuredClone(input);receipt=result;unconfirmed.value=true;error.value='正在演示回执未知状态；请核对同一次本地合成提交。';return}
  overlay.value='';emit('state','data')
 }catch(e){error.value=e instanceof Error?e.message:'合成记录未保存'}finally{busy.value=false}
}
async function confirm(){if(!attempt||!receipt||busy.value)return;busy.value=true;try{await readWatchlistReceipt(receipt,'tenant_example',attempt,'admin_example');unconfirmed.value=false;attempt=undefined;receipt=undefined;error.value='';overlay.value='';void router.replace({query:{...route.query,state:'data',list_state:undefined},hash:route.hash})}catch(e){error.value=e instanceof Error?e.message:'原合成提交未核对'}finally{busy.value=false}}
function applyState(){
 if(!ready.value)return
 if(unconfirmed.value){if(props.state==='action')resume();else overlay.value='';return}
 resetAction();overlay.value='';const row=route.query.list_state==='expired'?records.value.find(row=>row.id==='watch_expired_example'):records.value[0]
 if(!row||forbidden.value)return
 if(props.state==='detail')inspect(row)
 if(props.state==='action')edit(row)
 if(route.query.panel==='preview')inspectPreview(row)
}
watch([()=>props.state,()=>route.query.panel,()=>route.query.list_state],applyState)
void watchlistExamples().then(rows=>{if(disposed)return;records.value=rows;for(const row of rows)versions.set(row.id,[row,{...row,revision:1,active:false}]);ready.value=true;applyState()}).catch(e=>{if(!disposed){sourceError.value=e instanceof Error?e.message:'合成来源无法核验';ready.value=true}})
onScopeDispose(()=>{disposed=true;generation++})
</script>
<template>
 <PageHeader title="保护与观察名单" description="核对名单用途、固定探针范围、业务有效期和历史修订。"><a-button @click="emit('state','data')">刷新</a-button><a-button type="primary" :disabled="loading||forbidden||busy" @click="create">{{unconfirmed?'核对原提交':'创建名单'}}</a-button></PageHeader>
 <a-alert type="info" show-icon message="合成名单示例" :description="`示例观测时间：${watchlistExampleTime}。组件与输入校验复用工程实现；保存及核验仅作用于浏览器内存，不查询真实探针、不发布生产名单、不删除告警或调用设备。`" class="section-gap"/>
 <a-alert v-if="unconfirmed&&overlay!=='form'" type="warning" show-icon message="名单提交结果尚未确认" description="原合成请求与输入已保留，请点击核对原提交继续确认。" class="section-gap"/><section class="panel watchlist-filter"><form class="watchlist-query" @submit.prevent="search"><label for="preview-watchlist-keyword">名单名称<a-input id="preview-watchlist-keyword" v-model:value="keyword" aria-label="筛选名单名称" :maxlength="128" placeholder="名单名称" allow-clear/></label><label for="preview-watchlist-kind">名单类型<a-select id="preview-watchlist-kind" v-model:value="kind" :options="[{value:'',label:'全部类型'},...Object.entries(watchlistKinds).map(([value,label])=>({value,label}))]"/></label><label for="preview-watchlist-active">配置状态<a-select id="preview-watchlist-active" v-model:value="active" aria-label="筛选名单配置状态" :options="[{value:'',label:'全部配置状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]"/></label><a-space><a-button html-type="submit" type="primary">查询</a-button><a-button @click="resetFilters">重置</a-button></a-space></form></section>
 <section class="panel"><StatePanel v-if="loading||pageError" :state="loading?'loading':'error'" :description="pageError" @action="emit('state','data')"/><StatePanel v-else-if="!filtered.length" state="empty" title="暂无名单" description="当前示例范围内没有匹配记录，可调整筛选或创建停用名单。" action="创建名单" @action="create"/><WatchlistTable v-else :items="filtered" :now="watchlistExampleClock" :can-edit="!forbidden" :disabled="unconfirmed||busy" @inspect="inspect" @edit="edit" @preview="inspectPreview" @state="row=>edit(row,true)"/></section>
 <WatchlistForm v-if="overlay==='form'" :key="`${formRecord?.id??'create'}:${formRecord?.revision??0}`" :record="formRecord" :draft="draft" :busy="busy" :unconfirmed="unconfirmed" :error="error" :sensors="watchlistExampleSensors" :preview="preview" :preview-pending="previewPending" :preview-error="previewError" @change="clearPreview" @preview="runPreview" @save="save" @confirm="confirm" @close="close" @refresh-sensors="()=>{}"/>
 <WatchlistDetail v-else-if="overlay==='detail'" :record="detail" :revision="revision" :maximum="maximum" @read="read" @close="close"/>
 <WatchlistPreview v-else-if="overlay==='preview'&&selected" :key="`${selected.id}:${selected.revision}`" :record="selected" :result="preview" :input="previewInput" :pending="previewPending" :error="previewError" @change="clearPreview" @run="runPreview" @close="close"/>
</template>
<style scoped>
.watchlist-filter{padding:var(--panel-inset);margin-bottom:var(--section-gap)}
.watchlist-query{display:flex;gap:var(--related-gap);align-items:flex-end;flex-wrap:wrap}
.watchlist-query label{display:grid;gap:var(--label-gap);min-width:0}
.watchlist-filter :deep(.ant-select){min-width:160px}
</style>
