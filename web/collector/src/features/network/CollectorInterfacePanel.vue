<script setup lang="ts">
import type { NetworkInterface } from '@starbeacon/shared/types.ts';
import InterfaceTable from './InterfaceTable.vue';
defineProps<{ interfaces: NetworkInterface[] }>();
</script>
<template>
  <section class="panel">
    <div class="panel-header">
      <h2>网卡列表</h2>
    </div>
    <InterfaceTable :items="interfaces" />
  </section>
</template>
