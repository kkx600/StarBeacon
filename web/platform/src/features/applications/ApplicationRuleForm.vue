<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import {applicationCategories,applicationFields,applicationOperators,conditionOperators,domainCondition,changeError,type AppChange,type AppCondition,type AppRule} from './applicationRules'
const props=defineProps<{record:AppRule|null;draft?:AppChange;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:AppChange];confirm:[];close:[]}>()
const draft=props.draft,record=props.record,id=draft?.id??record?.id??'app_'+crypto.randomUUID().replaceAll('-','')
const definition=draft?.definition??record?.definition
type Row=AppCondition&{row:string}
const rows=(items:AppCondition[]):Row[]=>items.map(c=>({...c,row:crypto.randomUUID()}))
const form=reactive({name:draft?.name??record?.name??'',description:draft?.description??record?.description??'',active:String(draft?.active??record?.active??true),productID:definition?.product_id??'',productName:definition?.product_name??'',category:definition?.category_id??'business',protocols:definition?.protocols?[...definition.protocols]:['http'],any:rows(definition?.any??[{field:'http.host',op:'domain_suffix',value:''}]),all:rows(definition?.all??[]),exclude:rows(definition?.exclude??[])})
const localError=ref(''),errorPanel=ref<HTMLDivElement|null>(null),locked=computed(()=>props.busy||props.unconfirmed)
const groups=[{key:'any',label:'候选域名条件',help:'至少一个名称条件命中。共享域名只能形成产品候选。'},{key:'all',label:'同时满足条件',help:'所有附加条件均须命中；缺测时不补造。'},{key:'exclude',label:'排除条件',help:'任一排除条件命中时，该规则不参与识别。'}] as const
const count=computed(()=>form.any.length+form.all.length+form.exclude.length)
const categoryOptions=Object.entries(applicationCategories).map(([value,label])=>({value,label}))
function fieldOptions(positive:boolean){return Object.entries(applicationFields).filter(([field])=>(!positive||domainCondition(field))&&(field.startsWith('http.')?form.protocols.includes('http'):field.startsWith('tls.')?form.protocols.some(p=>p==='tls'||p==='quic'):form.protocols.includes('dns'))).map(([value,label])=>({value,label}))}
function add(group:'any'|'all'|'exclude'){
 if(locked.value||count.value>=32||group==='any'&&form.any.length>=16)return
 const field=fieldOptions(group==='any')[0]?.value as AppCondition['field']|undefined
 if(!field){localError.value='请先选择适用协议。';return}
 form[group].push({row:crypto.randomUUID(),field,op:domainCondition(field)?'domain_suffix':'eq',value:''})
}
function setField(row:Row,value:unknown){if(typeof value!=='string'||!Object.hasOwn(applicationFields,value))return;row.field=value as AppCondition['field'];row.op=domainCondition(value)?'domain_suffix':'eq';row.value=''}
function remove(group:'any'|'all'|'exclude',index:number){if(!locked.value&&!(group==='any'&&form.any.length===1))form[group].splice(index,1)}
function focusError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)focusError()},{flush:'post'})
function submit(){
 if(locked.value)return
 const condition=(values:Row[])=>values.map(({field,op,value})=>({field,op,value:value.trim()}))
 const input:AppChange={id,expected_revision:draft?.expected_revision??record?.revision??0,name:form.name.trim(),description:form.description.trim(),active:form.active==='true',definition:{schema_version:'application-rule.v1',product_id:form.productID.trim(),product_name:form.productName.trim(),category_id:form.category,protocols:[...form.protocols],any:condition(form.any),all:condition(form.all),exclude:condition(form.exclude)}}
 localError.value=changeError(input)
 if(!localError.value&&record&&input.name===record.name&&input.description===record.description&&input.active===record.active&&JSON.stringify(input.definition)===JSON.stringify(record.definition))localError.value='没有可提交的规则变更。'
 if(localError.value){focusError();return};emit('save',input)
}
</script>
<template>
 <a-modal :open="true" :title="record||draft?.expected_revision?'编辑应用识别规则':'创建应用识别规则'" :width="860" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" :mask-closable="false" :closable="!busy" :keyboard="!busy" @cancel="emit('close')">
  <a-alert type="info" show-icon message="名称规则只形成产品候选。保存配置不会发布到探针，不产生攻击告警，也不会封禁地址。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次提交结果尚未确认，字段已锁定，请核对原提交。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" tabindex="-1" role="region" aria-label="应用识别规则校验信息" class="section-gap"><a-alert type="error" show-icon :message="error||localError"/></div>
  <a-form layout="vertical" :model="form" :disabled="locked" @finish="submit">
   <div class="application-form-grid">
    <a-form-item label="规则名称" html-for="app-rule-name" required><a-input id="app-rule-name" v-model:value="form.name" :maxlength="128" autocomplete="off"/></a-form-item>
    <a-form-item label="规则状态" html-for="app-rule-active"><a-select id="app-rule-active" v-model:value="form.active" :disabled="locked||!record&&!draft?.expected_revision" :options="[{value:'true',label:'启用'},{value:'false',label:'停用'}]" @keydown.esc.stop/></a-form-item>
    <a-form-item label="产品标识" html-for="app-rule-product-id" required><a-input id="app-rule-product-id" v-model:value="form.productID" :maxlength="64" placeholder="小写字母、数字、下划线或连字符" autocomplete="off"/></a-form-item>
    <a-form-item label="产品名称" html-for="app-rule-product-name" required><a-input id="app-rule-product-name" v-model:value="form.productName" :maxlength="128" placeholder="业务应用或产品的正式名称"/></a-form-item>
    <a-form-item label="应用类别" html-for="app-rule-category"><a-select id="app-rule-category" v-model:value="form.category" :options="categoryOptions" @keydown.esc.stop/></a-form-item>
    <a-form-item label="适用协议" html-for="app-rule-protocols" required><a-select id="app-rule-protocols" v-model:value="form.protocols" mode="multiple" :options="['http','tls','quic','dns'].map(value=>({value,label:value.toUpperCase()}))" @keydown.esc.stop/></a-form-item>
   </div>
   <a-form-item label="维护说明" html-for="app-rule-description"><a-input id="app-rule-description" v-model:value="form.description" :maxlength="1000" placeholder="名称来源、适用范围与正负样本依据"/></a-form-item>
   <section v-for="group in groups" :key="group.key" class="application-conditions" :aria-label="group.label">
    <div class="application-condition-header"><h3>{{group.label}} · {{form[group.key].length}}</h3><a-button size="small" :disabled="locked||count>=32||group.key==='any'&&form.any.length>=16" @click="add(group.key)">添加条件</a-button></div>
    <p class="page-description">{{group.help}}</p>
    <div v-for="(row,index) in form[group.key]" :key="row.row" class="application-condition-row">
     <a-select :value="row.field" :aria-label="`${group.label} ${index+1} 字段`" :options="fieldOptions(group.key==='any')" @update:value="setField(row,$event)" @keydown.esc.stop/>
     <a-select v-model:value="row.op" :aria-label="`${group.label} ${index+1} 运算符`" :options="conditionOperators(row.field).map(value=>({value,label:applicationOperators[value]}))" @keydown.esc.stop/>
     <a-input v-model:value="row.value" :aria-label="`${group.label} ${index+1} 匹配值`" :maxlength="domainCondition(row.field)?1024:row.field==='http.path'?256:row.field==='http.user_agent'?128:64" :placeholder="domainCondition(row.field)?'精确域名，例如 files.example':'可见字段的匹配值'"/>
     <a-button :aria-label="`删除${group.label} ${index+1}`" :disabled="locked||group.key==='any'&&form.any.length===1" @click="remove(group.key,index)">删除</a-button>
    </div>
   </section>
   <p class="page-description">共 {{count}} / 32 条条件。域名匹配按标签边界与 IDNA 核对，不支持正则、公共后缀、IP 地址或 TLS 正文推断。</p>
   <div class="application-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :loading="busy" :disabled="locked">保存</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>
.application-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 12px}.application-conditions{border:1px solid var(--border-color,#e5e7eb);border-radius:8px;padding:10px;margin-bottom:10px}.application-condition-header,.application-actions{display:flex;align-items:center;justify-content:space-between;gap:8px}.application-condition-header h3{margin:0;font-size:14px}.application-condition-row{display:grid;grid-template-columns:150px 120px minmax(0,1fr) auto;gap:8px;margin-top:8px}.application-actions{justify-content:flex-end;margin-top:12px}.application-condition-row>*{min-width:0}@media(max-width:700px){.application-form-grid{grid-template-columns:minmax(0,1fr)}.application-condition-row{grid-template-columns:1fr 1fr}.application-condition-row input{grid-column:1/-1}}
</style>
