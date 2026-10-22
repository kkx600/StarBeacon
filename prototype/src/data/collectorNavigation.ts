import {collectorScreens,collectorWorkspaces,type CollectorView} from '../../../web/collector/src/navigation.ts'
import type {LocationQuery} from 'vue-router'

export {collectorScreens,collectorWorkspaces}
const legacyView:Record<string,CollectorView>={'replay-samples':'samples','replay-tasks':'tasks',responses:'responses',interfaces:'interfaces',capture:'capture',archives:'archives',syslog:'syslog',identity:'identity',samples:'samples',tasks:'tasks'}
export const collectorPrototypeScreens=collectorScreens.map(screen=>({...screen,path:`/collector${screen.path}`,page:screen.workspace==='rules'?'updates':screen.workspace==='response'?'network':screen.workspace==='connection'?'connection':screen.workspace==='overview'?'overview':'network'}))
export function collectorPreviewScreen(path:string,id:string,query:LocationQuery){
 const canonical=collectorPrototypeScreens.find(screen=>screen.path===path)
 if(canonical)return canonical
 const value=typeof query.view==='string'?legacyView[query.view]:undefined
 if(value)return collectorPrototypeScreens.find(screen=>screen.view===value)
 if(query.view)return undefined
 const defaults:Record<string,CollectorView>={overview:'overview',network:'interfaces',connection:'identity'}
 return collectorPrototypeScreens.find(screen=>screen.view===defaults[id])
}
export function collectorPreviewWorkspace(id:string,screen?:{workspace:string}){return screen?.workspace??({updates:'rules',maintenance:'overview'} as Record<string,string>)[id]??id}
export function collectorPreviewDestination(path:string,query:LocationQuery,hash:string){
 const {view:ignoredView,task:ignoredTask,...kept}=query
 return {path,query:kept,hash}
}
export const collectorTargetTabs=[
 {key:'maintenance-services',workspace:'overview',title:'服务与存储',path:'/collector/maintenance',view:'services'},
 {key:'maintenance-audits',workspace:'overview',title:'操作日志',path:'/collector/maintenance',view:'audits'},
 {key:'network-management',workspace:'network',title:'管理网络',path:'/collector/network',view:'management'},
 {key:'connection-setup',workspace:'connection',title:'接入配置',path:'/collector/connection',view:'setup'},
 {key:'updates-rules',workspace:'rules',title:'规则同步',path:'/collector/updates',view:'rules'},
 {key:'updates-system',workspace:'rules',title:'系统升级',path:'/collector/updates',view:'system'},
] as const
export function collectorPreviewCanonical(to:{path:string;query:LocationQuery;hash:string}){
 if(!collectorPrototypeScreens.some(screen=>screen.path===to.path)||!Object.prototype.hasOwnProperty.call(to.query,'view'))return
 const selected=typeof to.query.view==='string'?collectorPrototypeScreens.find(screen=>screen.view===to.query.view):undefined
 const {view:ignoredView,...query}=to.query
 return {path:selected?.path??to.path,query,hash:to.hash,replace:true}
}
