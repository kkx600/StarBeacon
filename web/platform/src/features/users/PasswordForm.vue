<script setup lang="ts">
import {computed,nextTick,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Form as AForm,FormItem as AFormItem,InputPassword as AInputPassword} from 'ant-design-vue'
import {passwordInputError,type PasswordInput} from './usePasswordChange'
import type {UserRecord} from './user'
const props=defineProps<{record:UserRecord;own:boolean;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:PasswordInput];confirm:[];reload:[]}>()
const form=reactive({currentPassword:'',newPassword:'',confirmation:''}),localError=shallowRef(''),errorNode=shallowRef<HTMLElement|null>(null)
const failure=computed(()=>props.error||localError.value),locked=computed(()=>props.busy||props.unconfirmed)
const rules={currentPassword:[{required:true,message:'请输入当前登录账号的密码。'}],newPassword:[{required:true,message:'请输入新密码。'}],confirmation:[{required:true,message:'请再次输入新密码。'}]}
watch(failure,async(value)=>{if(value){await nextTick();errorNode.value?.focus()}})
function validationFailed(result:{errorFields?:{errors?:string[]}[]}){localError.value=result.errorFields?.[0]?.errors?.[0]??'请填写完整的密码信息。'}
function submit(){
 if(locked.value)return
 const input:PasswordInput={expected_revision:props.record.revision,current_password:form.currentPassword,new_password:form.newPassword}
 localError.value=passwordInputError(input)
 if(!localError.value&&form.newPassword!==form.confirmation)localError.value='两次输入的新密码不一致，请重新核对。'
 if(!localError.value)emit('save',input)
}
onScopeDispose(()=>{form.currentPassword='';form.newPassword='';form.confirmation=''})
</script>
<template>
 <a-alert type="warning" show-icon class="section-gap" :message="own?'修改后需要重新登录':'重置后目标账号需要重新登录'"><template #description>目标账号的全部既有会话将被撤销。角色与启用状态保持当前配置；停用账号不会因密码重置自动启用。</template></a-alert>
 <p class="password-target">目标账号：<strong>{{record.username}}</strong> · 修订 {{record.revision}}</p>
 <div v-if="failure" ref="errorNode" tabindex="-1" role="alert" aria-label="密码表单校验信息" class="section-gap"><a-alert type="error" show-icon :message="failure"/></div>
 <a-alert v-if="unconfirmed" type="info" show-icon message="提交结果尚未确认，密码字段已锁定。" class="section-gap"><template #description>{{own?'如果原会话已失效，请使用新密码重新登录核对；不要重复创建密码操作。':'请核对原提交，或刷新目标账号后核对当前修订。此窗口关闭后会清除内存中的密码。'}}</template></a-alert>
 <a-form name="password-operation" :model="form" :rules="rules" layout="vertical" :disabled="locked" @finish="submit" @finish-failed="validationFailed">
  <a-form-item name="currentPassword" label="当前登录账号密码" required><a-input-password v-model:value="form.currentPassword" autocomplete="current-password" :maxlength="72" placeholder="验证当前操作者身份"/></a-form-item>
  <a-form-item name="newPassword" label="新密码" required><a-input-password v-model:value="form.newPassword" autocomplete="new-password" :maxlength="72" placeholder="12～72 个 UTF-8 字节"/></a-form-item>
  <a-form-item name="confirmation" label="确认新密码" required><a-input-password v-model:value="form.confirmation" autocomplete="new-password" :maxlength="72" placeholder="再次输入新密码"/></a-form-item>
  <div class="filter-actions"><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :loading="busy" :disabled="busy||record.revision>=1000000">{{own?'修改密码':'重置密码'}}</a-button><a-button :disabled="locked" @click="emit('reload')">刷新账号</a-button></div>
 </a-form>
</template>
<style scoped>.password-target{overflow-wrap:anywhere;margin:0 0 var(--section-gap)}.filter-actions{flex-wrap:wrap}</style>
