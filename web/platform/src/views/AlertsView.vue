<script setup lang="ts">
import AlertsWorkspace from '../features/alerts/AlertsWorkspace.vue'
defineProps<{window?:{start?:string;end?:string};advanced?:boolean}>()
</script>
<template><AlertsWorkspace :key="[window?.start,window?.end].join('|')" :window="window" :advanced="advanced" /></template>
