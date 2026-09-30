<script setup lang="ts">
defineProps<{title:string;description?:string;eyebrow?:string}>()
</script>
<template><div class="page-header"><div><div v-if="eyebrow" class="page-eyebrow">{{eyebrow}}</div><h1>{{title}}</h1><p v-if="description">{{description}}</p></div><div class="page-header-actions"><slot/></div></div></template>
