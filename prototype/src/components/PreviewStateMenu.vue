<script setup lang="ts">
import { computed } from 'vue';
import { usePreview } from '../composables/usePreview';
import { states } from '../data/catalog';

const { state, setState } = usePreview();
const label = computed(() => states.find(item => item.value === state.value)?.label);
function selectState({ key }: { key: string | number }) {
  const selected = states.find(item => item.value === key);
  if (selected) setState(selected.value);
}
</script>

<template>
  <a-dropdown :trigger="['click']">
    <a-button size="small" class="preview-state-button" :aria-label="`原型状态：${label}`">
      <span class="preview-state-prefix">原型状态：</span>{{ label }}
    </a-button>
    <template #overlay>
      <a-menu :selected-keys="[state]" @click="selectState">
        <a-menu-item v-for="item in states" :key="item.value">{{ item.label }}</a-menu-item>
      </a-menu>
    </template>
  </a-dropdown>
</template>

<style scoped>
@media (max-width: 1180px) {
  .preview-state-prefix {
    display: none;
  }
}
</style>
