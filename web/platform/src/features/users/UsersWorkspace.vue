<script setup lang="ts">
import {ref,shallowRef} from 'vue'
import {message,Table as ATable,Tag as ATag,Select as ASelect} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {useUsers} from './useUsers'
import {userRoles,type UserInput,type UserRecord} from './user'
import UserForm from './UserForm.vue'
import UserDetail from './UserDetail.vue'
import PasswordDialog from './PasswordDialog.vue'
const passwordRecord=shallowRef<UserRecord|null>(null)
const state=useUsers()
const {page,pending,error,cursors,selected,detailPending,detailError,busy,unconfirmed,actionError}=state
const role=ref(''),active=ref(''),detailOpen=ref(false),editorOpen=ref(false),editing=shallowRef<UserRecord|null>(null),draft=shallowRef<UserInput|undefined>()
const columns=[{title:'账号名称',dataIndex:'username',key:'username',width:220,ellipsis:true},{title:'用户角色',key:'role',width:130},{title:'账号状态',key:'active',width:110},{title:'创建时间',key:'created',width:190},{title:'变更时间',key:'updated',width:190},{title:'操作',key:'actions',width:90}]
function restoreAttempt(){const frozen=state.pendingInput();if(!frozen)return;draft.value=frozen.input;editing.value=frozen.id&&selected.value?.id===frozen.id?selected.value:null;detailOpen.value=false;editorOpen.value=true}
function openEditor(record:UserRecord|null){if(unconfirmed.value){restoreAttempt();return}editing.value=record;draft.value=undefined;state.clearActionError();detailOpen.value=false;editorOpen.value=true}
function showDetail(id:string){editorOpen.value=false;detailOpen.value=true;void state.select(id)}
async function saved(result:UserRecord|undefined){if(!result)return;editorOpen.value=false;draft.value=undefined;editing.value=null;message.success('用户操作已确认');showDetail(result.id)}
async function save(input:UserInput){await saved(await state.save(state.pendingInput()?.id??editing.value?.id??'',input))}
async function confirm(){await saved(await state.confirm())}
</script>
<template>
 <header class="page-header"><div><h1>用户管理</h1><p class="page-description">维护本租户的账号、角色与启用状态，权限变更同步撤销目标用户的既有会话。</p></div><div class="filter-actions"><a-button :loading="pending" @click="state.refresh">刷新</a-button><a-button v-if="unconfirmed" type="primary" @click="restoreAttempt">核对原提交</a-button><a-button v-else type="primary" @click="openEditor(null)">创建用户</a-button></div></header>
 <a-form :model="{role,active}" class="panel user-filters" layout="inline" @finish="state.search(role,active)"><a-form-item label="用户角色"><a-select v-model:value="role" aria-label="筛选用户角色" class="user-select" :options="[{value:'',label:'全部角色'},...Object.entries(userRoles).map(([value,label])=>({value,label}))]"/></a-form-item><a-form-item label="账号状态"><a-select v-model:value="active" aria-label="筛选账号状态" class="user-select" :options="[{value:'',label:'全部状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]"/></a-form-item><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="role='';active='';state.search('','')">重置</a-button></a-form>
 <section class="panel"><div class="panel-header"><h2>租户用户</h2><span>当前页 {{page.items.length}} 条</span></div><StatePanel :loading="pending" :error="error" :empty="!page.items.length" description="当前条件下没有用户。请调整筛选条件，或创建本租户账号。" @retry="state.refresh"><a-table size="middle" row-key="id" :data-source="page.items" :columns="columns" :pagination="false" :scroll="{x:930}"><template #bodyCell="{column,record}"><template v-if="column.key==='role'">{{userRoles[record.role as keyof typeof userRoles]}}</template><a-tag v-else-if="column.key==='active'" :color="record.active?'green':'default'">{{record.active?'启用':'停用'}}</a-tag><template v-else-if="column.key==='created'">{{formatTime(record.created_at)}}</template><template v-else-if="column.key==='updated'">{{formatTime(record.updated_at)}}</template><a-button v-else-if="column.key==='actions'" type="link" @click="showDetail(record.id)">查看</a-button></template></a-table></StatePanel><div class="user-pagination"><a-button :disabled="pending||cursors.length<=1" @click="state.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!page.next_cursor" @click="state.next">下一页</a-button></div></section>
 <UserDetail v-if="detailOpen" :record="selected" :pending="detailPending" :error="detailError" :self-id="session.current.value?.id??''" @close="detailOpen=false;state.clearSelection()" @reload="state.reloadDetail" @edit="openEditor(selected)" @password="passwordRecord=selected;detailOpen=false"/>
 <PasswordDialog v-if="passwordRecord" :record="passwordRecord" :own="false" @close="passwordRecord=null" @changed="state.refresh();state.reloadDetail()"/>
 <UserForm v-if="editorOpen" :key="(draft?'frozen_':'')+(editing?.id??'create')" :record="editing" :draft="draft" :self-id="session.current.value?.id??''" :busy="busy" :unconfirmed="unconfirmed" :error="actionError" @close="editorOpen=false" @save="save" @confirm="confirm"/>
</template>
<style scoped>.user-filters{display:flex;gap:var(--related-gap);flex-wrap:wrap;align-items:center;padding:var(--panel-inset);margin-bottom:var(--section-gap)}.user-filters .ant-form-item{margin:0}.user-select{min-width:150px}.user-pagination{display:flex;justify-content:flex-end;align-items:center;gap:var(--related-gap);padding:var(--panel-inset)}@media(max-width:700px){.user-filters .ant-form-item{flex:1 1 100%;min-width:0}.user-pagination{flex-wrap:wrap}}</style>
