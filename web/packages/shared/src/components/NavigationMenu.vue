<script setup lang="ts">
import {computed,shallowRef,watch,type VNode} from 'vue'
export interface NavigationItem {key:string;label:string;icon?:()=>VNode;title?:string;children?:NavigationItem[]}
const props=defineProps<{items:NavigationItem[];current:string;collapsed?:boolean}>()
const emit=defineEmits<{navigate:[key:string]}>()
const opened=shallowRef<string[]>([])
const ancestors=computed(()=>{
  function find(items:NavigationItem[],parents:string[]):string[]|undefined {
    for(const item of items){if(item.key===props.current)return parents;const nested=item.children&&find(item.children,[...parents,item.key]);if(nested)return nested}
  }
  return find(props.items,[])??[]
})
watch([()=>props.current,()=>props.collapsed,ancestors],()=>{opened.value=props.collapsed?[]:ancestors.value},{immediate:true})
</script>
<template><a-menu v-model:openKeys="opened" :selected-keys="[current]" mode="inline" :inline-collapsed="collapsed" :items="items" @click="({key}:{key:string})=>emit('navigate',key)"/></template>
