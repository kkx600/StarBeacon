<script setup lang="ts">
import {InboxOutlined,CloudOutlined,ReloadOutlined} from '@ant-design/icons-vue'
defineProps<{state:'empty'|'error'|'loading';title?:string;description?:string;action?:string}>()
defineEmits<{action:[]}>()
</script>
<template><div class="state-panel" role="status"><template v-if="state==='loading'"><a-spin size="large"/><h3>正在加载数据</h3><p>保留当前筛选条件，请稍候。</p><a-skeleton :paragraph="{rows:3}" active/></template><template v-else><span class="state-icon"><CloudOutlined v-if="state==='error'"/><InboxOutlined v-else/></span><h3>{{title??(state==='error'?'数据暂时无法加载':'暂无数据')}}</h3><p>{{description??(state==='error'?'数据服务暂时不可用，当前查询条件已保留。':'当前范围内没有可显示的记录。')}}</p><a-button type="primary" @click="$emit('action')"><ReloadOutlined v-if="state==='error'"/>{{action??(state==='error'?'重新加载':'创建记录')}}</a-button><small v-if="state==='error'">请求编号：DEMO-REQ-001</small></template></div></template>
