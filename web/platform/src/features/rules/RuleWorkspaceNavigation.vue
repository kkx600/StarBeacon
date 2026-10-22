<script setup lang="ts">
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {platformScreens} from '@starbeacon/shared/navigation.ts'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
const props=defineProps<{canManage:boolean}>(),route=useRoute(),router=useRouter()
const screens=computed(()=>platformScreens.filter(screen=>screen.workspace==='rules'&&screen.view&&screen.mode!=='rollouts'&&(!screen.admin||props.canManage)))
const items=computed(()=>screens.value.map(screen=>({key:screen.view!,label:screen.view==='sync'?'规则自动同步':screen.title})))
const active=computed(()=>screens.value.find(screen=>screen.path===route.path)?.view??String(route.meta.workspaceView??'packages'))
function change(key:string){
 const target=screens.value.find(screen=>screen.view===key)
 if(!target)return
 const {view:ignoredView,mode:ignoredMode,rule_id:ruleID,revision,...query}=route.query
 void router.push({path:target.path,query:{...query,...(key==='backtest'?{rule_id:ruleID,revision}:{})},hash:route.hash})
}
</script>
<template><WorkspaceTabs :active="active" :items="items" label="检测规则功能" @change="change"/></template>
