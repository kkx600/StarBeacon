<script setup lang="ts">
import {shallowRef} from 'vue'
import {Modal as AModal,Table as ATable,Tabs as ATabs} from 'ant-design-vue'
import MCPResourceGuide from '../../../web/platform/src/features/mcp/MCPResourceGuide.vue'
const ATabPane=ATabs.TabPane
const open=shallowRef(false),tab=shallowRef('tools')
const rows=[['alerts.search','告警检索','alerts:read'],['alerts.aggregate','态势统计','alerts:read'],['assets.get','资产详情','assets:read'],['sensors.list','探针列表','sensors:read'],['alerts.fields','告警检索字段','alerts:read'],['alerts.filter.validate','告警表达式校验','alerts:read'],['traffic.search','协议流量检索','traffic:read'],['traffic.fields','协议检索字段','traffic:read'],['traffic.filter.validate','协议表达式校验','traffic:read']].map(([name,title,scope])=>({name,title,scope}))
const columns=[{title:'工具',dataIndex:'name',width:240},{title:'用途',dataIndex:'title',width:180},{title:'只读权限',dataIndex:'scope',width:160}]
function openDirectory(){tab.value='tools';open.value=true}
</script>
<template>
 <a-button class="section-gap" @click="openDirectory">工具与资源</a-button>
 <a-modal :open="open" title="MCP 工具与资源" :width="980" :footer="null" :body-style="{maxHeight:'calc(100vh - 240px)',overflowY:'auto'}" @cancel="open=false"><a-alert type="info" show-icon message="接入说明" description="以下为静态接入目录，不代表当前身份已发现或获准使用全部工具和资源。原型不建立 MCP 会话，不读取真实业务数据。" class="section-gap"/><a-tabs v-model:active-key="tab"><a-tab-pane key="tools" tab="工具目录"><a-table :data-source="rows" :columns="columns" row-key="name" :pagination="false" :scroll="{x:620}"/></a-tab-pane><a-tab-pane key="resources" tab="元数据资源"><MCPResourceGuide/></a-tab-pane></a-tabs></a-modal>
</template>
