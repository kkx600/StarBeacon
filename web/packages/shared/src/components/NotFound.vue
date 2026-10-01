<script setup lang="ts">
defineProps<{home:string}>()
</script>
<template><main class="state-panel"><h1>页面不存在</h1><p>当前地址没有对应功能，请核对链接或返回工作区。</p><router-link :to="home"><a-button type="primary">返回工作区</a-button></router-link></main></template>
