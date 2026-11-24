<script setup lang="ts">
import PageHelp from './PageHelp.vue';

export interface PageHelpEntry {
  id: number | string;
  message: string;
  description?: string;
}
defineProps<{
  title: string;
  description?: string;
  notice?: string;
  helpEntries?: readonly PageHelpEntry[];
}>();
</script>

<template>
  <header class="page-header">
    <div class="page-heading">
      <h1 :title="title">{{ title }}</h1>
      <PageHelp v-if="description || notice || helpEntries?.length" :title="title">
        <p v-if="description">{{ description }}</p>
        <p v-if="notice">{{ notice }}</p>
        <p v-for="entry in helpEntries" :key="entry.id">
          <template v-if="entry.description"
            ><b>{{ entry.message }}</b> {{ entry.description }}</template
          >
          <template v-else>{{ entry.message }}</template>
        </p>
      </PageHelp>
    </div>
    <div v-if="$slots.default" class="page-header-actions"><slot /></div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--field-gap);
  min-height: 34px;
  margin-bottom: var(--related-gap);
}
.page-heading {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
}
.page-heading h1 {
  margin: 0;
  min-width: 0;
  font-size: 20px;
  line-height: 28px;
  font-weight: 600;
  letter-spacing: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.page-header-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  align-items: center;
  gap: var(--related-gap);
  flex: none;
  max-width: 70%;
}
@media (max-width: 1180px) {
  .page-header-actions > :slotted(.ant-space) {
    flex-wrap: wrap;
    justify-content: flex-end;
  }
}
</style>
