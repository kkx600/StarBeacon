<script setup lang="ts">
import { useRouter } from 'vue-router';
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue';

defineProps<{ active: 'devices' | 'plugins' }>();
const router = useRouter();
const items = [
  { key: 'devices', label: '联动设备' },
  { key: 'plugins', label: '联动插件' },
];
function change(key: string) {
  void router.push(key === 'plugins' ? '/response/plugins' : '/response/devices');
}
</script>

<template>
  <WorkspaceTabs :active="active" :items="items" label="联动设备功能" @change="change" />
</template>
