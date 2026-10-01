<script setup lang="ts">
defineProps<{error?:Error}>()
function reload(){window.location.reload()}
</script>
<template>
  <section class="state-panel" :role="error?'alert':'status'">
    <template v-if="error"><h3>工作区暂时无法打开</h3><p>页面资源加载失败，请刷新页面后重试。</p><a-button @click="reload">刷新页面</a-button></template>
    <template v-else><a-spin/><p>正在加载工作区</p></template>
  </section>
</template>
