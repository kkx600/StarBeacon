<script setup lang="ts">
import {onScopeDispose,shallowRef} from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import ProbeIdentitySummary from '@starbeacon/shared/components/ProbeIdentitySummary.vue'
import {useProbeIdentity} from './useProbeIdentity'
const {identity,pending,error,refresh}=useProbeIdentity()
const now=shallowRef(Date.now()),timer=setInterval(()=>{now.value=Date.now()},30000)
onScopeDispose(()=>clearInterval(timer))
</script>
<template><section class="panel section-gap"><div class="panel-header"><h2>平台通信身份</h2><a-button :loading="pending" @click="refresh">刷新证书状态</a-button></div><div class="panel-body"><StatePanel :loading="pending" :error="error" :empty="!identity" description="尚未取得本机证书状态。" @retry="refresh"><ProbeIdentitySummary v-if="identity" :identity="identity" :now="now" /></StatePanel></div></section></template>
