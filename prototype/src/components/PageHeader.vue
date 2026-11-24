<script setup lang="ts">
import SharedPageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';

const props = defineProps<{ title: string; description?: string; notice?: string }>();
</script>

<template>
  <SharedPageHeader v-bind="props" :help-entries="helpEntries">
    <template v-if="$slots.default" #default><slot /></template>
  </SharedPageHeader>
</template>
