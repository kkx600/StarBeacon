<script setup lang="ts">
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
const route=useRoute();const router=useRouter()
const code=computed(()=>String(route.params.code))
const title=computed(()=>code.value==='403'?'没有访问权限':code.value==='500'?'服务暂时不可用':code.value==='tenant'?'当前租户授权不足':'页面不存在')
const description=computed(()=>code.value==='403'?'当前身份未获准访问此对象，请核对角色、数据范围或联系租户管理员。':code.value==='500'?'数据服务暂时异常，当前业务状态不会被自动判定为成功或失败。请稍后重试。':code.value==='tenant'?'此功能不在当前租户的授权范围内，请切换有权限的组织或申请授权。':'页面地址不存在或对象已失效，请从页面目录选择可访问的功能。')
</script>
<template><div class="status-page panel"><a-result :status="code==='403'||code==='tenant'?'403':code==='500'?'500':'404'" :title="title" :sub-title="description"><template #extra><a-space><a-button type="primary" @click="router.push('/page/overview')">返回态势总览</a-button><a-button @click="router.push('/catalog')">页面目录</a-button><a-button v-if="code==='500'" @click="router.push('/page/platform-health')">重新检查服务</a-button></a-space><p class="muted">示例请求编号：DEMO-REQ-001 · 对象访问仍受授权控制</p></template></a-result></div></template>
