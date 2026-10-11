<script setup lang="ts">
import {shallowRef} from 'vue'
import {Table,Modal,Popconfirm,message} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {useMCP} from './useMCP'
import {bindingState,scopeNames,type Scope,type Binding,type BindingChange} from './mcp'
import BindingForm from './BindingForm.vue'
const state=useMCP(),{items,info,pending,error,busy,actionError}=state
const editing=shallowRef<Binding|null>(null),editorOpen=shallowRef(false),toolsOpen=shallowRef(false)
const columns=[{title:'服务身份',key:'name',width:180},{title:'授权主体 / OAuth 客户端',key:'identity',width:270},{title:'只读权限',key:'scopes',width:190},{title:'状态',key:'state',width:90},{title:'到期时间',key:'expiry',width:190},{title:'调用上限',key:'budget',width:110},{title:'操作',key:'actions',fixed:'right' as const,width:150}]
function edit(record:Binding|null){state.clearActionError();editing.value=record;editorOpen.value=true}
async function save(change:BindingChange){if(await state.save(change)){editorOpen.value=false;message.success('服务身份配置已保存')}}
async function remove(record:Binding){if(await state.remove(record))message.success('服务身份已删除')}
function date(value:string){const at=new Date(value);return Number.isFinite(at.getTime())?at.toLocaleString('zh-CN',{hour12:false}):'时间无效'}
</script>
<template>
  <header class="page-header"><div><h1>模型配置</h1><p class="page-description">管理其他 Agent 的只读数据分析接入、租户授权及调用预算。</p></div><div class="filter-actions"><a-button :loading="pending" @click="state.refresh">刷新</a-button><a-button @click="toolsOpen=true">工具目录</a-button><a-button type="primary" :disabled="pending||busy||!info?.enabled||items.length>=100" @click="edit(null)">登记服务身份</a-button></div></header>
  <a-alert v-if="actionError&&!editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert v-if="!pending&&!error&&!info?.enabled" type="info" message="MCP 服务尚未启用。部署管理员需配置 HTTPS 公开来源、OAuth 授权方与受限令牌内省凭据。" show-icon class="section-gap" />
  <section v-if="info?.enabled" class="panel mcp-connection"><div><span class="muted">接入地址</span><code>{{info.resource}}</code></div><div><span class="muted">授权方</span><code>{{info.issuer}}</code></div><div><span class="muted">资源发现</span><code>{{info.metadata_url}}</code></div><p class="page-description">HTTP POST · Bearer 认证 · 无持久协议会话。支持协议：{{info.protocol_versions.join('、')}}。</p></section>
  <section class="panel"><div class="panel-header"><h2>MCP 服务身份</h2><span>{{items.length}} / 100 个身份</span></div><StatePanel :loading="pending" :error="error" :empty="items.length===0" description="暂无服务身份。启用 MCP 后，可登记调用方的主体与客户端，并授予只读权限。" @retry="state.refresh"><div class="table-wrap"><Table :columns="columns" :data-source="[...items]" row-key="id" :pagination="false" :scroll="{x:1180}"><template #bodyCell="{column,record}">
    <template v-if="column.key==='name'">{{record.name}}<small class="record-id">修订 {{record.revision}}</small></template><template v-else-if="column.key==='identity'"><span class="mcp-identity">{{record.subject}}</span><small class="record-id mcp-identity">{{record.oauth_client_id}}</small></template><template v-else-if="column.key==='scopes'"><span v-for="scope in record.scopes" :key="scope" class="mcp-scope">{{scopeNames[scope as Scope]??scope}}</span></template><template v-else-if="column.key==='state'"><span :class="['status',bindingState(record as Binding)==='启用'?'status-online':'status-disabled']">{{bindingState(record as Binding)}}</span></template><template v-else-if="column.key==='expiry'">{{date(record.expires_at)}}</template><template v-else-if="column.key==='budget'">{{record.requests_per_minute}} 次 / 分钟</template><template v-else-if="column.key==='actions'"><div class="filter-actions"><a-button type="link" size="small" :disabled="busy||!info?.enabled" @click="edit(record as Binding)">配置</a-button><Popconfirm title="删除此服务身份？" description="该身份的后续调用会被拒绝，已有操作日志仍按保留策略保存。" ok-text="删除身份" cancel-text="取消" :disabled="busy" @confirm="remove(record as Binding)"><a-button type="link" size="small" danger :disabled="busy">删除</a-button></Popconfirm></div></template>
  </template></Table></div></StatePanel></section>
  <BindingForm v-if="editorOpen&&info" :record="editing" :issuer="info.issuer" :pending="busy" :error="actionError" @save="save" @close="editorOpen=false" />
  <Modal v-if="toolsOpen" :open="true" title="MCP 工具目录" :width="680" :footer="null" @cancel="toolsOpen=false"><ul class="mcp-tools"><li v-for="tool in info?.tools??[]" :key="tool.name"><strong>{{tool.title}}</strong><code>{{tool.name}}</code><p>{{tool.description}}</p><span class="muted">需要权限：{{scopeNames[tool.scope]??tool.scope}}</span></li></ul><p class="page-description">工具只执行已实现的有界查询，不能直接访问数据库、运行命令或执行封禁。调用结果与错误写入操作日志。</p></Modal>
</template>
<style scoped>.mcp-connection{display:grid;gap:var(--related-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.mcp-connection>div{display:grid;grid-template-columns:80px minmax(0,1fr);gap:var(--related-gap)}.mcp-connection code,.mcp-identity{overflow-wrap:anywhere;word-break:break-word}.mcp-scope{display:block}.mcp-tools{padding-left:20px}.mcp-tools li{margin-bottom:var(--section-gap)}.mcp-tools code{display:block;color:var(--text-secondary);overflow-wrap:anywhere}.mcp-tools p{margin:var(--related-gap) 0}</style>
