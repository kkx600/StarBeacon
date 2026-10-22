<script setup lang="ts">
import {useRoute,useRouter} from 'vue-router'
import {Result as AResult} from 'ant-design-vue'
import {safeReturnPath} from '@starbeacon/shared/utils/history.ts'
const route=useRoute(),router=useRouter()
function login(){void router.replace({path:'/login',query:{redirect:safeReturnPath(route.query.redirect,'/overview/status')}})}
</script>
<template><header class="page-header"><div><h1>访问受限</h1><p class="page-description">当前账号没有采集器本地管理权限。请使用具有管理权限的账号登录。</p></div></header><section class="panel"><AResult status="403" title="无法访问采集器管理功能" sub-title="采集器运行状态、采集配置和任务记录均需本地管理员权限。"><template #extra><a-button type="primary" @click="login">返回登录</a-button></template></AResult></section></template>
