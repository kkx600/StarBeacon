import {readFile,readdir,lstat} from 'node:fs/promises'
import {createHash} from 'node:crypto'

export const renderRoots=['prototype/src','web/platform/src','web/collector/src','web/packages/shared/src']
export async function digestRenderTree(project){
  const paths=[]
  for(const root of renderRoots){
    for(const path of await readdir(new URL(root+'/',project),{recursive:true})){
      if(!/\.(vue|ts|css|json|svg)$/.test(path))continue
      const full=root+'/'+path.replaceAll('\\','/')
      const info=await lstat(new URL(full,project))
      if(info.isSymbolicLink())throw new Error('界面源码目录不允许符号链接')
      if(info.isFile())paths.push(full)
    }
  }
  const hash=createHash('sha256')
  for(const path of paths.sort()){hash.update(path+'\0');hash.update(await readFile(new URL(path,project)));hash.update('\0')}
  return {sha256:hash.digest('hex'),files:paths.length}
}
