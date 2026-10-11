<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import {managementInputError,type ManagementTarget,type ManagementInput,type SensorGroup} from './management'
const props=defineProps<{target:ManagementTarget;draft?:ManagementInput;groups:readonly SensorGroup[];groupsPending:boolean;groupsError:string;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[kind:'group'|'metadata',id:string,input:ManagementInput];confirm:[];close:[];reloadGroups:[]}>()
const group=computed(()=>props.target.kind==='group'),record=props.target.record
const id=props.draft&&'id' in props.draft?props.draft.id:record?.id??'sg_'+crypto.randomUUID().replaceAll('-','')
const model=reactive({name:props.draft?.name??record?.name??'',description:props.draft?.description??record?.description??'',active:String(props.draft&&'active' in props.draft?props.draft.active:props.target.kind==='group'?props.target.record?.active??true:true),groupID:props.draft&&'group_id' in props.draft?props.draft.group_id:props.target.kind==='metadata'?props.target.record.group_id??'':'',site:props.draft&&'site' in props.draft?props.draft.site:props.target.kind==='metadata'?props.target.record.site??'':''})
const localError=ref(''),errorPanel=ref<HTMLDivElement|null>(null)
const locked=computed(()=>props.busy||props.unconfirmed)
const groupOptions=computed(()=>[{value:'',label:'未分组'},...props.groups.map(g=>({value:g.id,label:g.name}))])
function focusError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)focusError()},{flush:'post'})
function submit(){
 if(locked.value)return
 if(!group.value&&(props.groupsPending||props.groupsError)){localError.value='可用分组尚未完整返回，请先刷新分组。';focusError();return}
 const input:ManagementInput=props.target.kind==='group'?{id,expected_revision:props.draft?.expected_revision??props.target.record?.revision??0,name:model.name.trim(),description:model.description.trim(),active:model.active==='true'}:{expected_revision:props.draft?.expected_revision??props.target.record.metadata_revision??0,registration_id:props.draft&&'registration_id' in props.draft?props.draft.registration_id:props.target.record.registration_id,name:model.name.trim(),group_id:model.groupID,site:model.site.trim(),description:model.description.trim()}
 localError.value=managementInputError(input)
 if(!localError.value&&props.target.record){const r=props.target.record;if(group.value&&'revision' in r&&r.name===input.name&&r.description===input.description&&'active' in input&&r.active===input.active||!group.value&&'registration_id' in input&&'registration_id' in r&&r.name===input.name&&(r.description??'')===input.description&&(r.site??'')===input.site&&(r.group_id??'')===input.group_id)localError.value='没有可提交的管理信息变更。'}
 if(localError.value){focusError();return}
 emit('save',props.target.kind,id,input)
}
</script>
<template>
 <a-modal :open="true" :title="group?(record?'编辑探针分组':'创建探针分组'):'编辑探针信息'" :width="620" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <a-alert type="info" show-icon :message="group?'分组用于管理归类。停用前需移出全部成员，停用记录可重新启用。':'管理名称、分组和站点独立于证书身份、网卡配置与设备执行权限。'" class="section-gap" />
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次提交结果尚未确认，字段已锁定，请核对原提交。" class="section-gap" />
  <div v-if="localError||error" ref="errorPanel" tabindex="-1" role="region" aria-label="探针管理表单校验信息" class="section-gap"><a-alert type="error" show-icon :message="localError||error" /></div>
  <a-form :model="model" layout="vertical" :disabled="locked" @finish="submit">
   <a-form-item :label="group?'分组名称':'探针名称'" html-for="sensor-management-name" required><a-input id="sensor-management-name" v-model:value="model.name" :maxlength="128" autocomplete="off" /></a-form-item>
   <template v-if="!group">
    <a-alert v-if="groupsError" type="error" show-icon :message="groupsError" class="section-gap"><template #action><a-button size="small" :disabled="locked" @click="emit('reloadGroups')">刷新分组</a-button></template></a-alert>
    <a-form-item label="探针分组" html-for="sensor-management-group"><a-select id="sensor-management-group" v-model:value="model.groupID" :options="groupOptions" :loading="groupsPending" :disabled="locked||groupsPending||!!groupsError" show-search option-filter-prop="label" @keydown.esc.stop /></a-form-item>
    <a-form-item label="部署站点" html-for="sensor-management-site"><a-input id="sensor-management-site" v-model:value="model.site" :maxlength="128" placeholder="例如总部机房、分支办公区" /></a-form-item>
   </template>
   <a-form-item label="说明" html-for="sensor-management-description"><a-input id="sensor-management-description" v-model:value="model.description" :maxlength="1000" /></a-form-item>
   <a-form-item v-if="group" label="分组状态" html-for="sensor-management-active"><a-select id="sensor-management-active" v-model:value="model.active" :disabled="locked||!record" :options="[{value:'true',label:'启用'},{value:'false',label:'停用'}]" @keydown.esc.stop /><p v-if="record&&'member_count' in record&&record.member_count" class="page-description">当前有 {{record.member_count}} 台探针，包括已停用的探针。请先迁移或移出全部成员后停用。</p></a-form-item>
   <div class="management-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :loading="busy" :disabled="locked||!group&&(groupsPending||!!groupsError)">保存</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.management-actions{display:flex;justify-content:flex-end;flex-wrap:wrap;gap:var(--related-gap)}</style>
