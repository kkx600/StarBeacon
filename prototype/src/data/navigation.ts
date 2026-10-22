import {pages} from './catalog.ts'
import {navigationWorkspaces,platformScreens} from '../../../web/packages/shared/src/navigation.ts'
export const nestedPages:Record<string,string>={discovery:'assets','rule-rollouts':'rule-sync','correlation-backtest':'correlation'}
export const workspaces=navigationWorkspaces.map(workspace=>({...workspace,pages:[...workspace.pages,...platformScreens.filter(screen=>screen.workspace===workspace.id&&!workspace.pages.includes(screen.id)&&!nestedPages[screen.id]&&pages.some(page=>page.id===screen.id)).map(screen=>screen.id)]}))
export type {WorkspaceSpec} from '../../../web/packages/shared/src/navigation.ts'

export const workspaceById=new Map(workspaces.map(workspace=>[workspace.id,workspace]))
export const workspaceForPage=new Map(workspaces.flatMap(workspace=>workspace.pages.map(id=>[id,workspace] as const)))
for(const [child,parent] of Object.entries(nestedPages)){const workspace=workspaceForPage.get(parent);if(workspace)workspaceForPage.set(child,workspace)}
export const legacyPages:Record<string,string>={'sensor-health':'sensors','pcap-downloads':'pcap-tasks','operation-logs':'audit'}
export const accountPages=pages.filter(page=>page.id==='my-account')

export function workspaceTitleForPage(id:string):string {
  return workspaceForPage.get(id)?.title??pages.find(page=>page.id===id)?.title??'页面目录'
}

export function pageIdForRoute(route:{meta:Record<string,unknown>;params:Record<string,unknown>}):string {return String(route.meta.previewPage??route.params.id)}
export function prototypePath(id:string):string {return platformScreens.find(screen=>screen.id===id)?.path??`/page/${id}`}
