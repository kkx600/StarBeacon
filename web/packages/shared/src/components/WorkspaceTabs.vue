<script setup lang="ts">
import {Tabs as ATabs} from 'ant-design-vue'
const ATabPane=ATabs.TabPane
defineProps<{active:string;items:{key:string;label:string}[];label:string}>()
const emit=defineEmits<{change:[key:string]}>()
</script>
<template><nav class="workspace-tabs" :aria-label="label"><a-tabs :active-key="active" @change="key=>emit('change',String(key))"><a-tab-pane v-for="item in items" :key="item.key" :tab="item.label"/></a-tabs></nav></template>
<style>.workspace-tabs {margin-bottom:var(--section-gap);min-width:0}.workspace-tabs .ant-tabs-nav {margin:0}.workspace-tabs .ant-tabs-content-holder {display:none}.workspace-tabs .ant-tabs-tab {padding:8px 0}</style>
