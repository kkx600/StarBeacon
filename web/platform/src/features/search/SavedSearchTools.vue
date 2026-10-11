<script setup lang="ts">
import {computed,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {parserVersion,savedWindowLabel,type Dataset,type SavedChange,type SavedDefinition,type SavedQuery,type SavedResolution} from './savedSearch'
import {useSavedSearches} from './useSavedSearches'
import QuerySummary from './QuerySummary.vue'
import SaveQueryForm from './SaveQueryForm.vue'
const props=defineProps<{dataset:Dataset;current:SavedDefinition;disabled:boolean}>()
const emit=defineEmits<{apply:[value:SavedResolution]}>()
const {page,filter,cursors,loading,busy,resolving,error,mutationError,unconfirmed,load,search,next,previous,save,confirm,pendingInput,clearError,resolve,canEdit}=useSavedSearches(()=>props.dataset)
const library=shallowRef(false),detail=shallowRef<SavedQuery|null>(null),form=shallowRef<{record:SavedQuery|null}|null>(null)
const listForm=reactive({keyword:'',visibility:'' as ''|'personal'|'team',active:'true' as ''|'true'|'false'})
const locked=computed(()=>busy.value||resolving.value),draft=computed(()=>unconfirmed.value?pendingInput():undefined)
async function openLibrary(){library.value=true;await search({...listForm})}
function openForm(record:SavedQuery|null){if(locked.value||unconfirmed.value)return;clearError();library.value=false;detail.value=null;form.value={record}}
function reopen(){if(busy.value)return;library.value=false;detail.value=null;form.value={record:null}}
async function submit(input:SavedChange){const result=await save(input);if(result){form.value=null;await load()}}
async function confirmOriginal(){const result=await confirm();if(result){form.value=null;await load()}}
async function apply(record:SavedQuery){if(props.disabled||locked.value||loading.value)return;const value=await resolve(record);if(value){library.value=false;detail.value=null;emit('apply',value)}}
function resetFilter(){Object.assign(listForm,{keyword:'',visibility:'',active:'true'});void search({...listForm})}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,props.dataset].join('/'),()=>{library.value=false;detail.value=null;form.value=null;Object.assign(listForm,{keyword:'',visibility:'',active:'true'})})
</script>
<template>
 <div class="saved-query-tools"><a-button :disabled="props.disabled||locked||unconfirmed" @click="openForm(null)">保存当前查询</a-button><a-button :disabled="locked" @click="openLibrary">已保存查询</a-button><a-button v-if="unconfirmed" :disabled="busy" @click="reopen">核对原提交</a-button></div>
 <a-modal v-if="library" :open="true" title="已保存查询" :width="820" :footer="null" :mask-closable="false" :closable="!locked" :keyboard="!locked" @cancel="library=false">
  <p class="page-description">{{dataset==='alerts'?'告警':'协议记录'}}查询 · 个人查询仅自己可见，团队查询按当前账号权限执行。</p>
  <a-form :model="listForm" layout="vertical" @finish="search({...listForm})"><div class="saved-query-filters"><a-form-item label="查询名称" html-for="saved-library-keyword"><a-input id="saved-library-keyword" v-model:value="listForm.keyword" :maxlength="128" :disabled="loading||locked" allow-clear/></a-form-item><a-form-item label="可见范围" html-for="saved-library-visibility"><a-select id="saved-library-visibility" v-model:value="listForm.visibility" :disabled="loading||locked" :options="[{label:'全部可见查询',value:''},{label:'仅自己',value:'personal'},{label:'团队共享',value:'team'}]" @keydown.esc.stop/></a-form-item><a-form-item label="查询状态" html-for="saved-library-active"><a-select id="saved-library-active" v-model:value="listForm.active" :disabled="loading||locked" :options="[{label:'启用',value:'true'},{label:'停用',value:'false'},{label:'全部状态',value:''}]" @keydown.esc.stop/></a-form-item></div><div class="query-actions"><a-button html-type="submit" :disabled="loading||locked">筛选</a-button><a-button :disabled="loading||locked" @click="resetFilter">重置</a-button><a-button :loading="loading" :disabled="locked" @click="load">刷新查询</a-button></div></a-form>
  <StatePanel :loading="loading" :error="error" :empty="!page.items.length" description="当前条件下没有保存查询。完成检索后可保存常用条件。" @retry="load">
   <ul class="saved-query-list" aria-label="保存查询列表"><li v-for="record in page.items" :key="record.id"><div class="saved-query-content"><strong>{{record.name}}</strong><span class="query-state">{{record.visibility==='personal'?'仅自己':'团队共享'}} · {{record.active?'启用':'停用'}} · {{savedWindowLabel(record.definition.window)}}</span><p v-if="record.description">{{record.description}}</p><small>修订 {{record.revision}} · {{formatTime(record.updated_at)}}<span v-if="record.definition.parser_version!==parserVersion" class="query-incompatible"> · 解析器不兼容</span></small></div><div class="query-row-actions"><a-button size="small" :disabled="locked" @click="detail=record;library=false">查看</a-button><a-button size="small" type="primary" :disabled="props.disabled||locked||!record.active||record.definition.parser_version!==parserVersion" @click="apply(record)">应用</a-button><a-button v-if="canEdit(record)" size="small" :disabled="locked||unconfirmed" @click="openForm(record)">编辑</a-button></div></li></ul>
  </StatePanel>
  <div class="query-pagination"><span>第 {{cursors.length}} 页 · 本页 {{page.items.length}} 个查询</span><div class="query-actions"><a-button :disabled="loading||locked||cursors.length<2" @click="previous">上一页</a-button><a-button :disabled="loading||locked||!!error||!page.next_cursor" @click="next">下一页</a-button></div></div>
 </a-modal>
 <a-modal v-if="detail" :open="true" :title="detail.name" :width="720" :footer="null" :mask-closable="false" :closable="!resolving" :keyboard="!resolving" @cancel="detail=null">
  <p>{{detail.description||'未填写用途说明'}}</p><QuerySummary :definition="detail.definition"/><a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/><a-alert v-if="!detail.active" type="warning" show-icon message="该查询已停用，不能应用。" class="section-gap"/><a-alert v-if="detail.definition.parser_version!==parserVersion" type="warning" show-icon message="过滤语法版本不兼容。请核对当前字段与语法，再由所有者重新保存。" class="section-gap"/><div class="query-actions"><a-button :disabled="resolving" @click="detail=null;openLibrary()">返回列表</a-button><a-button type="primary" :loading="resolving" :disabled="props.disabled||!detail.active||detail.definition.parser_version!==parserVersion" @click="apply(detail)">应用查询</a-button></div>
 </a-modal>
 <SaveQueryForm v-if="form" :record="form.record" :current="current" :draft="draft" :busy="busy" :unconfirmed="unconfirmed" :error="mutationError" @save="submit" @confirm="confirmOriginal" @close="form=null"/>
</template>
<style scoped>.saved-query-tools,.query-actions,.query-row-actions{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap,8px)}.saved-query-filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0 12px;margin-top:12px}.saved-query-list{list-style:none;padding:0;margin:16px 0}.saved-query-list li{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:12px 0;border-bottom:1px solid var(--border-color,#d9e0e8)}.saved-query-content{min-width:0;overflow-wrap:anywhere}.saved-query-content strong{display:block;color:var(--text-primary,#1f2937)}.saved-query-content p{margin:4px 0}.query-state,.saved-query-content small{display:block;font-size:12px;color:var(--text-secondary,#475569)}.query-incompatible{color:var(--color-danger,#b91c1c)}.query-row-actions{flex-shrink:0}.query-pagination{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-top:12px}@media(max-width:1100px){.saved-query-list li{align-items:flex-start;flex-wrap:wrap}.query-row-actions{flex-shrink:1}}</style>
