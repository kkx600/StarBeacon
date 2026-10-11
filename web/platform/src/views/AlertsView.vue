<script setup lang="ts">
import AlertsWorkspace from '../features/alerts/AlertsWorkspace.vue'
defineProps<{window?:{start?:string;end?:string}}>()
</script>
<template><AlertsWorkspace :key="[window?.start,window?.end].join('|')" :window="window" /></template>
