<script setup lang="ts">
import OverviewWorkspace from '../features/overview/OverviewWorkspace.vue'
defineProps<{screen?:boolean}>()
</script>
<template><OverviewWorkspace :screen="screen"/></template>
