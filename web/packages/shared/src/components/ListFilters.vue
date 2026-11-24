<script setup lang="ts">
withDefaults(defineProps<{ label?: string; wide?: boolean; columns?: 1 | 2 | 3 | 4; embedded?: boolean }>(), {
  label: '检索条件',
});
</script>

<template>
  <section class="panel filter-panel" :aria-label="label" :data-embedded="embedded || undefined">
    <div class="filter-grid" :class="{ 'filter-grid-wide': wide }" :data-columns="columns">
      <slot />
      <div v-if="$slots.actions" class="filter-buttons"><slot name="actions" /></div>
    </div>
    <div v-if="$slots.advanced" class="filter-grid advanced-filters"><slot name="advanced" /></div>
  </section>
</template>
