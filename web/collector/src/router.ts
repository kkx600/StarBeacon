import { createRouter, createWebHistory } from 'vue-router'
import {migrateLegacyHash} from '@starbeacon/shared/utils/history.ts'
import { session } from './session'
migrateLegacyHash(import.meta.env.BASE_URL)
export const router = createRouter({history:createWebHistory(import.meta.env.BASE_URL),scrollBehavior:()=>({top:0}),routes:[{path:'/',redirect:'/network'},{path:'/login',component:()=>import('./views/LoginView.vue')},{path:'/network',component:()=>import('./views/CollectorView.vue')},{path:'/:pathMatch(.*)*',component:()=>import('@starbeacon/shared/components/NotFound.vue'),props:{home:'/network'}}]})
router.beforeEach(async to=>{if(to.path==='/login')return;try{await session.restore()}catch{return {path:'/login',query:{redirect:to.fullPath}}};if(!session.current.value)return {path:'/login',query:{redirect:to.fullPath}}})
