import {computed,inject} from 'vue'
import {routeLocationKey} from 'vue-router'
export function usePageTitle(fallback:string){
  const route=inject(routeLocationKey,undefined)
  return computed(()=>typeof route?.meta.title==='string'?route.meta.title:fallback)
}
