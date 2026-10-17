<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {Modal as AModal} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {usePasswordChange,type PasswordInput} from './usePasswordChange'
import type {UserRecord} from './user'
import PasswordForm from './PasswordForm.vue'
const message=useFeedback()
const props=defineProps<{record?:UserRecord;own:boolean}>()
const emit=defineEmits<{close:[];changed:[]}>()
const state=usePasswordChange(props.record??null,props.own)
async function submitted(input?:PasswordInput){
 const result=input?await state.save(input):await state.confirm()
 if(!result)return
 message.success(props.own?'密码已修改，请重新登录。':'密码重置已确认，目标账号的既有会话已撤销。')
 emit('changed');emit('close')
 if(props.own)session.api.onUnauthorized?.()
}
</script>
<template>
 <a-modal :open="true" :title="own?'修改密码':'重置密码'" :width="560" :footer="null" :closable="!state.busy.value" :mask-closable="!state.busy.value" :keyboard="!state.busy.value" @cancel="emit('close')">
  <StatePanel :loading="state.pending.value" :error="state.error.value" :empty="!state.record.value" description="当前账号信息暂不可用，请刷新后核对。" @retry="state.reload"><PasswordForm v-if="state.record.value" :key="state.record.value.revision" :record="state.record.value" :own="own" :busy="state.busy.value" :unconfirmed="state.unconfirmed.value" :error="state.actionError.value" @save="submitted" @confirm="submitted()" @reload="state.reload"/></StatePanel>
 </a-modal>
</template>
