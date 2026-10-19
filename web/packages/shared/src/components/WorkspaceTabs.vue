<script setup lang="ts">
import {Tabs as ATabs} from 'ant-design-vue'
import {computed,inject} from 'vue'
import {routeLocationKey} from 'vue-router'
const ATabPane=ATabs.TabPane
const props=defineProps<{active:string;items:{key:string;label:string}[];label:string}>()
const route=inject(routeLocationKey,undefined)
const visible=computed(()=>{const allowed=route?.meta.allowedViews;if(!Array.isArray(allowed)||!allowed.length)return props.items;const filtered=props.items.filter(item=>allowed.includes(item.key));return filtered.length?filtered:props.items})
const emit=defineEmits<{change:[key:string]}>()
</script>
<template><nav v-if="visible.length>1" class="workspace-tabs" :aria-label="label"><a-tabs :active-key="active" @change="key=>emit('change',String(key))"><a-tab-pane v-for="item in visible" :key="item.key" :tab="item.label"/></a-tabs></nav></template>
<style>.workspace-tabs {margin-bottom:var(--section-gap);min-width:0}.workspace-tabs .ant-tabs-nav {margin:0}.workspace-tabs .ant-tabs-content-holder {display:none}.workspace-tabs .ant-tabs-tab {padding:8px 0}</style>
