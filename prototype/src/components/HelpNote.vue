<script setup lang="ts">
import { onBeforeUnmount, watch } from 'vue';
import { registerHelp } from '../composables/pageHelp';

// 把一段静态说明登记到页面标题旁的“说明”里，自身不在页面上占位置。
const props = defineProps<{ message: string; description?: string }>();
let release: (() => void) | undefined;
watch(
  () => [props.message, props.description],
  () => {
    release?.();
    release = registerHelp({ message: props.message, description: props.description });
  },
  { immediate: true },
);
onBeforeUnmount(() => release?.());
</script>

<template>
  <span v-if="false" />
</template>
