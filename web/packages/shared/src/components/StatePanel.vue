<script setup lang="ts">
defineProps<{loading?: boolean; error?: string; empty?: boolean; description?: string}>()
const emit = defineEmits<{retry: []}>()
</script>
<template>
  <div v-if="loading" class="state-panel" role="status"><a-spin /><p>正在读取数据</p></div>
  <div v-else-if="error" class="state-panel" role="alert"><h3>暂时无法读取数据</h3><p>{{ error }}</p><a-button @click="emit('retry')">重试</a-button></div>
  <div v-else-if="empty" class="state-panel"><a-empty :description="description ?? '暂无记录'" /></div>
  <slot v-else />
</template>
