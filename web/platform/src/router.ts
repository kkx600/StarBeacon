import { createRouter, createWebHistory } from 'vue-router'
import {migrateLegacyHash} from '@starbeacon/shared/utils/history.ts'
import { session } from './session'
migrateLegacyHash(import.meta.env.BASE_URL)
export const router = createRouter({history: createWebHistory(import.meta.env.BASE_URL), scrollBehavior:()=>({top:0}), routes: [
  {path: '/', redirect: '/sensors'},
  {path: '/login', component: () => import('./views/LoginView.vue')},
  {path:'/overview',component:()=>import('./views/OverviewView.vue')},
  {path:'/screen',component:()=>import('./views/OverviewView.vue'),props:{screen:true}},
  {path: '/sensors', component: () => import('./views/SensorsView.vue')},
  {path: '/rules', component: () => import('./views/RulesView.vue')},
  {path: '/alerts', component: () => import('./views/AlertsView.vue'),props:route=>({window:{start:typeof route.query.start==='string'?route.query.start:undefined,end:typeof route.query.end==='string'?route.query.end:undefined}})},
  {path:'/traffic',component:()=>import('./views/TrafficView.vue')},
  {path: '/assets',component:()=>import('./views/InventoryView.vue')},
  {path:'/operations',component:()=>import('./views/OperationsView.vue'),meta:{admin:true}},
  {path:'/notifications',component:()=>import('./views/NotificationsView.vue'),meta:{admin:true}},
  {path:'/models',component:()=>import('./views/ModelsView.vue'),meta:{admin:true}},
  {path:'/assistant',component:()=>import('./views/AssistantView.vue'),meta:{admin:true}},
  {path:'/reports',component:()=>import('./views/ReportsView.vue'),meta:{admin:true}},
  {path:'/retention',component:()=>import('./views/RetentionView.vue'),meta:{admin:true}},
  {path:'/incidents',component:()=>import('./views/IncidentsView.vue'),meta:{admin:true}},
  {path:'/users',component:()=>import('./views/UsersView.vue'),meta:{admin:true}},
  {path: '/:pathMatch(.*)*', component:()=>import('@starbeacon/shared/components/NotFound.vue'),props:{home:'/sensors'}},
]})
router.beforeEach(async to => {if (to.path === '/login') return; try {await session.restore()} catch {return {path:'/login',query:{redirect:to.fullPath}}}; if (!session.current.value) return {path:'/login',query:{redirect:to.fullPath}};if(to.meta.admin&&session.current.value.role!=='admin')return '/sensors'})
