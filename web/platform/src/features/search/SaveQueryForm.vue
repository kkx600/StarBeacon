<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {Checkbox as ACheckbox,Modal as AModal,Select as ASelect} from 'ant-design-vue'
import {session} from '../../session'
import {changeError,copyDefinition,editSaved,sameDefinition,type SavedChange,type SavedDefinition,type SavedQuery} from './savedSearch'
import QuerySummary from './QuerySummary.vue'
const props=defineProps<{record:SavedQuery|null;current:SavedDefinition;draft?:SavedChange;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:SavedChange];confirm:[];close:[]}>()
const initial:SavedChange=props.draft??(props.record?editSaved(props.record):{id:'sq_'+crypto.randomUUID().replaceAll('-',''),expected_revision:0,expected_generation_id:'',name:'',description:'',visibility:'personal',active:true,definition:copyDefinition(props.current)})
const form=reactive({name:initial.name,description:initial.description,visibility:initial.visibility,active:String(initial.active),replace:false})
const locked=computed(()=>props.busy||props.unconfirmed),localError=ref(''),errorPanel=ref<HTMLDivElement|null>(null)
const definition=computed(()=>props.unconfirmed?(props.draft?.definition??initial.definition):form.replace?props.current:initial.definition)
const sharing=computed(()=>[{value:'personal',label:'仅自己'},...(session.current.value?.role==='admin'?[{value:'team',label:'团队共享'}]:[])])
function focusError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)focusError()},{flush:'post'})
watch(()=>props.draft,value=>{if(value&&props.unconfirmed)Object.assign(form,{name:value.name,description:value.description,visibility:value.visibility,active:String(value.active),replace:false})})
function submit(){
 if(locked.value)return
 const input:SavedChange={...initial,name:form.name.trim(),description:form.description.trim(),visibility:form.visibility,active:form.active==='true',definition:copyDefinition(definition.value)}
 localError.value=changeError(input)
 if(!localError.value&&props.record&&input.name===props.record.name&&input.description===props.record.description&&input.visibility===props.record.visibility&&input.active===props.record.active&&sameDefinition(input.definition,props.record.definition))localError.value='没有可提交的查询变更。'
 if(localError.value){focusError();return}
 emit('save',input)
}
</script>
<template>
 <a-modal :open="true" :title="initial.expected_revision?'编辑保存查询':'保存当前查询'" :width="680" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <a-alert type="info" show-icon message="保存查询条件和时间窗口。团队共享仅共享查询定义，不授予数据权限。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次提交结果尚未确认，字段已锁定，请核对原提交。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" role="region" tabindex="-1" aria-label="保存查询校验信息" class="section-gap"><a-alert type="error" show-icon :message="localError||error"/></div>
  <a-form :model="form" layout="vertical" :disabled="locked" @finish="submit">
   <a-form-item label="查询名称" html-for="saved-query-name" required><a-input id="saved-query-name" v-model:value="form.name" :maxlength="128" autocomplete="off"/></a-form-item>
   <a-form-item label="用途说明" html-for="saved-query-description"><a-input id="saved-query-description" v-model:value="form.description" :maxlength="1000"/></a-form-item>
   <div class="query-options"><a-form-item label="可见范围" html-for="saved-query-visibility"><a-select id="saved-query-visibility" v-model:value="form.visibility" :options="sharing" @keydown.esc.stop/></a-form-item><a-form-item v-if="record" label="查询状态" html-for="saved-query-active"><a-select id="saved-query-active" v-model:value="form.active" :options="[{label:'启用',value:'true'},{label:'停用',value:'false'}]" @keydown.esc.stop/></a-form-item></div>
   <a-checkbox v-if="record&&!unconfirmed" v-model:checked="form.replace" :disabled="locked">使用当前页面的查询条件和时间窗口</a-checkbox>
   <QuerySummary :definition="definition"/>
   <p class="page-description">相对窗口在每次应用时重新计算。固定窗口保持原起止时间，列表分页不作为保存条件。</p>
   <div class="query-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :disabled="busy" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :disabled="locked" :loading="busy">保存</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.query-options{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:0 12px}.query-actions{display:flex;justify-content:flex-end;gap:var(--related-gap,8px);flex-wrap:wrap;margin-top:12px}</style>
