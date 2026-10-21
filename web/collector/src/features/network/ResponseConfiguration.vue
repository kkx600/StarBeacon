<script setup lang="ts">
import {onScopeDispose,shallowRef} from 'vue'
import {readConfigCheck,type ConfigCheck} from '@starbeacon/shared/responseDevices.ts'
import ResponseConfigCheckDialog from '@starbeacon/shared/components/ResponseConfigCheckDialog.vue'
import {session} from '../../session'
const open=shallowRef(false),result=shallowRef<ConfigCheck|null>(null),pending=shallowRef(false),error=shallowRef('')
let controller:AbortController|undefined
async function check(){open.value=true;controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value='';result.value=null
 try{const value=readConfigCheck(await session.api.request('/response-config-check',{signal:current.signal}));if(!current.signal.aborted)result.value=value}catch(cause){if(!current.signal.aborted)error.value=cause instanceof Error?cause.message:'本地配置读取失败'}finally{if(controller===current)pending.value=false}}
function close(){open.value=false;controller?.abort();pending.value=false}
onScopeDispose(()=>controller?.abort())
</script>
<template><div class="configuration-check"><span class="page-description">核对本机文件与运行配置是否一致。</span><a-button @click="check">核对本地配置</a-button></div><ResponseConfigCheckDialog :open="open" :result="result" :pending="pending" :error="error" @retry="check" @close="close"/></template>
<style scoped>.configuration-check{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);margin-bottom:var(--section-gap)}</style>
