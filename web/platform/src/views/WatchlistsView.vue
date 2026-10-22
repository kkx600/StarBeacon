<script setup lang="ts">
import {computed} from 'vue'
import WatchlistsWorkspace from '../features/watchlists/WatchlistsWorkspace.vue'
import {session} from '../session'
const identity=computed(()=>{const user=session.current.value;return user?[user.tenant_id,user.id,user.role,user.csrf_token].join(':'):''})
</script>
<template><WatchlistsWorkspace :key="identity"/></template>
