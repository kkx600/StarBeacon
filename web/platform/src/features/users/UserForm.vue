<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import {userRoles,userInputError,type UserInput,type UserRecord} from './user'
const props=defineProps<{record:UserRecord|null;draft?:UserInput;busy:boolean;unconfirmed:boolean;error:string;selfId:string}>()
const emit=defineEmits<{save:[input:UserInput];confirm:[];close:[]}>()
const editing=computed(()=>!!props.record||!!props.draft&&'expected_revision' in props.draft)
const model=reactive({username:props.draft&&'username' in props.draft?props.draft.username:props.record?.username??'',password:props.draft&&'password' in props.draft?props.draft.password:'',role:props.draft?.role??props.record?.role??'viewer',active:String(props.draft?.active??props.record?.active??true)})
const locked=computed(()=>props.busy||props.unconfirmed||props.record?.id===props.selfId)
const localError=ref(''),errorPanel=ref<HTMLDivElement|null>(null)
function revealError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)revealError()},{flush:'post'})
function submit(){
 if(locked.value)return
 const input:UserInput=editing.value?{expected_revision:props.draft&&'expected_revision' in props.draft?props.draft.expected_revision:props.record!.revision,role:model.role,active:model.active==='true'}:{username:model.username,password:model.password,role:model.role,active:model.active==='true'}
 localError.value=userInputError(input)
 if(!localError.value&&props.record?.role===input.role&&props.record?.active===input.active)localError.value='没有可提交的角色或状态变更。'
 if(localError.value){revealError();return}
 emit('save',input)
}
</script>
<template>
 <a-modal :open="true" :title="editing?'编辑用户':'创建用户'" :width="640" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="!busy" @cancel="emit('close')">
  <a-alert show-icon type="info" :message="editing?'角色或状态变更成功后，目标用户的既有会话失效，需要重新登录。':'账号名称创建后保持不变。管理员可维护本租户配置，只读用户可查看获授权的数据。'" class="section-gap"/>
  <a-alert v-if="record?.id===selfId" show-icon type="warning" message="当前登录账号受保护，权限变更需由其他管理员处理。" class="section-gap"/>
  <a-alert v-if="unconfirmed" show-icon type="warning" message="上次提交结果尚未确认。字段已锁定，请使用原请求核对。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" tabindex="-1" role="region" aria-label="用户表单校验信息" class="section-gap"><a-alert show-icon type="error" :message="localError||error"/></div>
  <a-form :model="model" layout="vertical" :disabled="locked" @finish="submit">
   <a-form-item label="账号名称" html-for="user-name" required><a-input id="user-name" v-model:value="model.username" autocomplete="off" :readonly="editing" :maxlength="64"/></a-form-item>
   <a-form-item v-if="!editing" label="登录密码" html-for="user-password" required><a-input-password id="user-password" v-model:value="model.password" autocomplete="new-password" :maxlength="72" :visibility-toggle="false"/><p class="user-hint">12～72 个 UTF-8 字节，中文字符通常占 3 字节。</p></a-form-item>
   <div class="user-form-grid">
    <a-form-item label="用户角色" html-for="user-role" required><a-select id="user-role" v-model:value="model.role" :options="Object.entries(userRoles).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <a-form-item label="账号状态" html-for="user-active" required><a-select id="user-active" v-model:value="model.active" :options="[{value:'true',label:'启用'},{value:'false',label:'停用'}]" @keydown.esc.stop/></a-form-item>
   </div>
   <div class="user-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :loading="busy" :disabled="locked">{{editing?'提交变更':'创建用户'}}</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.user-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 var(--related-gap)}.user-actions{display:flex;gap:var(--related-gap);justify-content:flex-end;flex-wrap:wrap}.user-hint{font-size:12px;color:var(--text-secondary);margin:6px 0 0}@media(max-width:700px){.user-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
