<script setup lang="ts">
withDefaults(defineProps<{ label?: string; wide?: boolean }>(), { label: '检索条件' });
</script>

<template>
  <section class="panel filter-panel" :aria-label="label">
    <div class="filter-grid" :class="{ 'filter-grid-wide': wide }">
      <slot />
      <div v-if="$slots.actions" class="filter-buttons"><slot name="actions" /></div>
    </div>
    <div v-if="$slots.advanced" class="filter-grid advanced-filters"><slot name="advanced" /></div>
  </section>
</template>
