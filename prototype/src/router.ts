import { createRouter, createWebHashHistory } from 'vue-router'

export const router=createRouter({
  history:createWebHashHistory(),
  routes:[
    {path:'/',redirect:'/page/overview'},
    {path:'/page/:id',component:()=>import('./views/PageView.vue')},
    {path:'/catalog',component:()=>import('./views/CatalogView.vue')},
    {path:'/auth/:mode',component:()=>import('./views/AuthView.vue')},
    {path:'/status/:code',component:()=>import('./views/StatusView.vue')},
    {path:'/:pathMatch(.*)*',redirect:'/status/404'},
  ],
  scrollBehavior:()=>({top:0}),
})
