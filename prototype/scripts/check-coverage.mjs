import {readFile,writeFile,mkdir} from 'node:fs/promises'
import {pages,groups,states} from '../src/data/catalog.ts'
import {workspaces,legacyPages,accountPages} from '../src/data/navigation.ts'
const matrix=await readFile(new URL('../../docs/功能覆盖与验收矩阵.md',import.meta.url),'utf8')
const required=[...new Set(matrix.match(/SB-[A-Z]+-\d{3}/g))].sort()
const actual=[...new Set(pages.flatMap(p=>p.requirement))].sort()
const missing=required.filter(id=>!actual.includes(id));const extra=actual.filter(id=>!required.includes(id))
const duplicate=pages.map(p=>p.id).filter((id,i,all)=>all.indexOf(id)!==i)
const incomplete=pages.filter(p=>!p.title||!p.description||!p.columns.length||!p.fields.length||!p.primary||!p.emptyDescription)
if(missing.length||extra.length||duplicate.length||incomplete.length){console.error({missing,extra,duplicate,incomplete:incomplete.map(p=>p.id)});process.exit(1)}
const members=workspaces.flatMap(workspace=>workspace.pages)
const orphans=pages.filter(page=>!members.includes(page.id)&&!accountPages.some(account=>account.id===page.id))
const duplicates=members.filter((id,index)=>members.indexOf(id)!==index)
const invalid=workspaces.flatMap(workspace=>workspace.pages.filter(id=>!pages.some(page=>page.id===id&&page.group===workspace.group)))
const badAliases=Object.entries(legacyPages).filter(([legacy,id])=>pages.some(page=>page.id===legacy)||!pages.some(page=>page.id===id))
if(orphans.length||duplicates.length||invalid.length||badAliases.length){console.error({orphans:orphans.map(page=>page.id),duplicates,invalid,badAliases});process.exit(1)}
const boundary=[{id:'auth-login',title:'登录',url:'/auth/login'},{id:'auth-mfa',title:'多因素认证',url:'/auth/mfa'},{id:'auth-reset',title:'找回密码',url:'/auth/reset'},{id:'auth-expired',title:'会话过期',url:'/auth/expired'},{id:'status-403',title:'无访问权限',url:'/status/403'},{id:'status-404',title:'页面不存在',url:'/status/404'},{id:'status-500',title:'服务异常',url:'/status/500'},{id:'status-tenant',title:'租户授权不足',url:'/status/tenant'}]
const manifest={product:'星烽 StarBeacon',synthetic:true,requirementCount:required.length,workspaces,legacyPages,groups,states,boundary,pages:pages.map(p=>({id:p.id,title:p.title,group:p.group,kind:p.kind,description:p.description,requirements:p.requirement,states:states.map(s=>({state:s.value,title:s.label,url:`/page/${p.id}?state=${s.value}`,image:`${p.id}/${s.value}.jpg`}))}))}
await mkdir(new URL('../public/',import.meta.url),{recursive:true})
await writeFile(new URL('../public/page-manifest.json',import.meta.url),JSON.stringify(manifest,null,2)+'\n')
await writeFile(new URL('../public/page-manifest.js',import.meta.url),`window.StarBeaconPageManifest = ${JSON.stringify(manifest)};\n`)
console.log(`覆盖核对通过：${required.length} 项需求，${workspaces.length} 个主导航工作区，${pages.length} 个功能视图，${pages.length*states.length} 个业务状态，${boundary.length} 个边界页面。`)
