import {legacyPages} from './data/navigation'
import { createRouter, createWebHashHistory } from 'vue-router'

export const router=createRouter({
  history:createWebHashHistory(),
  routes:[
    {path:'/',redirect:'/page/overview'},
    ...Object.entries(legacyPages).map(([legacy,id])=>({path:`/page/${legacy}`,redirect:(to:import('vue-router').RouteLocation)=>({path:`/page/${id}`,query:to.query,hash:to.hash})})),
    {path:'/page/:id',component:()=>import('./views/PageView.vue')},
    {path:'/catalog',component:()=>import('./views/CatalogView.vue')},
    {path:'/auth/:mode',component:()=>import('./views/AuthView.vue')},
    {path:'/status/:code',component:()=>import('./views/StatusView.vue')},
    {path:'/:pathMatch(.*)*',redirect:'/status/404'},
  ],
  scrollBehavior:()=>({top:0}),
})
