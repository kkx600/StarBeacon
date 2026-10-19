import manifest from './navigation.json' with {type:'json'}

export interface WorkspaceSpec {id:string;title:string;group:string;pages:string[]}
export interface PlatformScreen {id:string;workspace:string;path:string;title:string;module:string;view?:string;mode?:string;admin?:boolean}

// 原型与实际平台以同一份目录核对业务归属和可用入口。
export const navigationGroups=manifest.groups
export const navigationWorkspaces:WorkspaceSpec[]=manifest.workspaces
export const platformScreens:PlatformScreen[]=manifest.screens

export function workspacePath(workspace:WorkspaceSpec):string {
  return platformScreens.find(screen=>screen.workspace===workspace.id)?.path??`/${(manifest.group_paths as Record<string,string>)[workspace.group]??workspace.group}/${workspace.id}`
}

