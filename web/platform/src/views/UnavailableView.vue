<script setup lang="ts">
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {Result as AResult} from 'ant-design-vue'
const route=useRoute(),router=useRouter()
const title=computed(()=>String(route.meta.title??'功能页面'))
</script>
<template><header class="page-header"><div><h1>{{title}}</h1></div></header><section class="panel"><a-result status="info" title="当前版本未提供此功能" sub-title="此入口保留在原有业务目录中，当前没有可操作的数据与配置。"><template #extra><a-button type="primary" @click="router.push('/system/settings')">查看系统设置</a-button><a-button @click="router.push('/overview/dashboard')">返回态势总览</a-button></template></a-result></section></template>
