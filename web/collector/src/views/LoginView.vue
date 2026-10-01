<script setup lang="ts">
import { useRoute,useRouter } from 'vue-router'
import {safeReturnPath} from '@starbeacon/shared/utils/history.ts'
import LoginForm from '@starbeacon/shared/components/LoginForm.vue'
import { session } from '../session'
const router=useRouter(),route=useRoute()
async function submit(username:string,password:string){if(await session.login(username,password))await router.replace(safeReturnPath(route.query.redirect,'/network'))}
</script>
<template><LoginForm title="登录采集器" :pending="session.pending.value" :error="session.error.value" @submit="submit" /></template>
