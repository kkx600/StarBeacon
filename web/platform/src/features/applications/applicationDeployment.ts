import {validApplicationState,type ApplicationState} from '@starbeacon/shared/application.ts'
import {appDigest,orderedDefinition,validDefinition,type AppDefinition} from './applicationRules'
export interface AppSnapshot {rules_sha256:string;versions:{id:string;revision:number;definition:AppDefinition}[]}
export interface AppDeploymentInput {expected_registration_id:string;expected_state_sha256:string;rules_sha256:string}
export interface AppTarget {id:string;name:string;registration_id:string;observed_at:string;state:ApplicationState}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
export async function validAppSnapshot(v:unknown):Promise<boolean>{
 if(!object(v)||typeof v.rules_sha256!=='string'||!Array.isArray(v.versions)||v.versions.length>128)return false
 let previous=''
 const versions:AppSnapshot['versions']=[]
 for(const entry of v.versions){if(!object(entry)||!id(entry.id)||entry.id<=previous||!Number.isSafeInteger(entry.revision)||Number(entry.revision)<1||Number(entry.revision)>1000000||!validDefinition(entry.definition))return false;previous=entry.id;versions.push({id:entry.id,revision:Number(entry.revision),definition:orderedDefinition(entry.definition as AppDefinition)})}
 return await appDigest(versions)===v.rules_sha256
}
export async function applicationTargets(value:unknown,now=Date.now()):Promise<AppTarget[]>{
 if(!object(value)||!Array.isArray(value.items)||value.items.length>10000)throw new Error('探针目录不完整或超过选择范围，请核对探针管理服务。')
 const targets:AppTarget[]=[],seen=new Set<string>()
 for(const row of value.items){
  if(!object(row)||!id(row.id)||seen.has(row.id)||!id(row.registration_id)||typeof row.name!=='string'||typeof row.active!=='boolean'||!['online','offline','disabled'].includes(String(row.status))||!object(row.health))throw new Error('探针目录包含无法核对的设备身份。')
  seen.add(row.id)
  const h=row.health
  if(!row.active||row.status!=='online'||typeof h.observed_at!=='string'||!Array.isArray(h.task_capabilities)||!h.task_capabilities.includes('applications.apply')||now-Date.parse(h.observed_at)>35000||Date.parse(h.observed_at)>now+60000||!Number.isFinite(Date.parse(h.observed_at))||!await validApplicationState(h.application_rules))continue
  targets.push({id:row.id,name:row.name,registration_id:row.registration_id,observed_at:h.observed_at,state:h.application_rules as ApplicationState})
 }
 return targets
}
export function deploymentTargetFresh(target:AppTarget,now=Date.now()):boolean{return now-Date.parse(target.observed_at)<=35000&&Date.parse(target.observed_at)<=now+60000}
