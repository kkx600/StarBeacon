<script setup lang="ts">
import {computed,shallowRef} from 'vue'
import {useRouter} from 'vue-router'
import {Table as ATable,Select as ASelect,Tag as ATag} from 'ant-design-vue'
import {navigationGroups,navigationWorkspaces,platformScreens,workspacePath} from '@starbeacon/shared/navigation.ts'
const router=useRouter(),keyword=shallowRef(''),scope=shallowRef('system')
const rows=computed(()=>navigationWorkspaces.filter(item=>item.id!=='settings'&&(scope.value==='all'||item.group==='system')&&`${item.title}${navigationGroups.find(group=>group.id===item.group)?.title}`.includes(keyword.value.trim())).map(item=>({...item,groupTitle:navigationGroups.find(group=>group.id===item.group)!.title,available:platformScreens.some(screen=>screen.workspace===item.id),path:workspacePath(item)})))
const columns=[{title:'功能分组',dataIndex:'groupTitle',width:160},{title:'功能名称',dataIndex:'title',width:180},{title:'可用范围',key:'scope'},{title:'操作',key:'action',width:120}]
</script>
<template>
 <header class="page-header"><div><h1>系统设置</h1><p class="page-description">统一查找账号、运行状态、留存与审计配置，核对当前版本的功能范围。</p></div></header>
 <a-form class="panel settings-filters" layout="inline" :model="{keyword,scope}" @finish="()=>{}"><a-form-item label="功能名称"><a-input v-model:value="keyword" placeholder="查找设置项" allow-clear/></a-form-item><a-form-item label="目录范围"><a-select v-model:value="scope" :options="[{value:'system',label:'系统管理'},{value:'all',label:'全部功能'}]" class="settings-scope"/></a-form-item></a-form>
 <section class="panel"><div class="panel-header"><h2>设置目录</h2><span>当前 {{rows.length}} 项</span></div><ATable :columns="columns" :data-source="rows" row-key="id" :pagination="false" :scroll="{x:700}" :locale="{emptyText:'没有匹配的设置项，请调整查找条件。'}"><template #bodyCell="{column,record}"><template v-if="column.key==='scope'"><a-tag :color="record.available?'blue':undefined">{{record.available?'提供功能入口':'当前版本未提供'}}</a-tag><span>{{record.available?'具体权限与可用状态以功能页面为准':'不提供配置保存与执行操作'}}</span></template><template v-else-if="column.key==='action'"><a-button type="link" :disabled="!record.available" @click="router.push(record.path)">进入管理</a-button></template></template></ATable></section>
</template>
<style scoped>.page-header{display:flex;gap:var(--section-gap);margin-bottom:var(--section-gap)}.page-header h1{font-size:20px;line-height:1.4;margin:0}.page-description{color:var(--muted);font-size:14px;margin:6px 0 0}.panel-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}.panel-header h2{font-size:14px;margin:0}.settings-filters{display:flex;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.settings-filters .ant-form-item{margin:0}.settings-scope{min-width:160px}</style>
