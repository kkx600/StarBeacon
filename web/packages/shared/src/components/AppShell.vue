<script setup lang="ts">
import { shallowRef, type VNode } from 'vue'
import { SafetyCertificateOutlined, MenuFoldOutlined, MenuUnfoldOutlined, LogoutOutlined } from '@ant-design/icons-vue'
defineProps<{title: string; username: string; current: string; items: {key: string; label: string; icon: () => VNode}[]}>()
const emit = defineEmits<{navigate: [path: string]; logout: []}>()
const collapsed = shallowRef(false)
const mobileMenu = shallowRef(false)
function toggleMenu() {if (window.matchMedia('(max-width: 550px)').matches) mobileMenu.value = true; else collapsed.value = !collapsed.value}
function navigate(path: string) {mobileMenu.value = false; emit('navigate', path)}
</script>

<template>
  <a-layout class="app-shell">
    <a-layout-sider :collapsed="collapsed" :width="220" theme="light" collapsible :trigger="null" breakpoint="lg" :collapsed-width="64" aria-label="主导航" @collapse="(value: boolean) => collapsed = value">
      <div class="brand"><SafetyCertificateOutlined class="brand-symbol" /><span v-if="!collapsed">星烽 <b>StarBeacon</b><small>{{ title }}</small></span></div>
      <a-menu :selected-keys="[current]" mode="inline" :inline-collapsed="collapsed" :items="items" @click="({key}: {key: string}) => navigate(key)" />
    </a-layout-sider>
    <a-layout>
      <a-layout-header class="app-header">
        <a-button type="text" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="toggleMenu"><MenuUnfoldOutlined v-if="collapsed" /><MenuFoldOutlined v-else /></a-button>
        <span class="header-title">{{ title }}</span><span class="header-user">{{ username }}</span>
        <a-button type="text" @click="emit('logout')"><LogoutOutlined />退出</a-button>
      </a-layout-header>
      <a-layout-content class="app-content"><slot /></a-layout-content>
    </a-layout>
  </a-layout>
  <a-drawer title="主导航" placement="left" :open="mobileMenu" :width="220" @close="mobileMenu = false"><a-menu :selected-keys="[current]" :items="items" @click="({key}: {key: string}) => navigate(key)" /></a-drawer>
</template>
