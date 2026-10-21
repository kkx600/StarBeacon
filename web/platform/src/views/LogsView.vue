<script setup lang="ts">
import SyslogLogs from '@starbeacon/shared/components/SyslogLogs.vue'
import {session} from '../session'
</script>
<template><SyslogLogs :api="session.api" :principal="session.current.value"/></template>
