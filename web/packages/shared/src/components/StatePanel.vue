<script setup lang="ts">
defineProps<{
  loading?: boolean;
  error?: string | boolean;
  empty?: boolean;
  title?: string;
  description?: string;
  action?: string;
}>();
const emit = defineEmits<{ retry: []; action: [] }>();
</script>
<template>
  <div v-if="loading" class="state-panel" role="status">
    <a-spin />
    <p>正在读取数据</p>
  </div>
  <div v-else-if="error" class="state-panel" role="alert">
    <h3>{{ title ?? '暂时无法读取数据' }}</h3>
    <p>{{ typeof error === 'string' ? error : '服务异常，请稍后重试。' }}</p>
    <a-button @click="emit('retry')">{{ action ?? '重试' }}</a-button>
  </div>
  <div v-else-if="empty" class="state-panel">
    <a-empty :description="title ? undefined : (description ?? '暂无记录')">
      <template v-if="title" #description>
        <strong class="empty-heading" role="heading" aria-level="3">{{ title }}</strong>
        <span v-if="description">{{ description }}</span>
      </template>
      <template v-if="action" #default>
        <a-button type="primary" @click="emit('action')">{{ action }}</a-button>
      </template>
    </a-empty>
  </div>
  <slot v-else />
</template>

<style scoped>
.state-panel {
  min-height: 280px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: var(--related-gap);
  padding: var(--panel-inset);
  text-align: center;
  color: var(--muted);
}
.state-panel h3,
.state-panel p {
  margin: 0;
  line-height: 1.6;
  max-width: 65ch;
}
.empty-heading {
  display: block;
  line-height: 1.6;
}
</style>
