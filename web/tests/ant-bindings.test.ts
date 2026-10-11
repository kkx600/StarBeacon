import {readdirSync,readFileSync} from 'node:fs'
import {resolve,sep} from 'node:path'
import {describe,expect,it} from 'vitest'
import {createApp} from 'vue'
import {compileScript,compileTemplate,parse} from 'vue/compiler-sfc'
import {registerAnt} from '../packages/shared/src/ant'

const root=resolve(process.cwd())+sep
function components(directory:string):string[]{
 return readdirSync(directory,{withFileTypes:true}).flatMap(entry=>{
  const path=resolve(directory,entry.name)
  return entry.isDirectory()?components(path):entry.name.endsWith('.vue')?[path]:[]
 })
}

describe('界面组件绑定',()=>{
 it('主平台、采集器与共享组件中的 Ant 标签均有实际组件绑定',()=>{
  const app=registerAnt(createApp({})),unregistered:string[]=[]
  const files=['platform/src','collector/src','packages/shared/src'].flatMap(path=>components(resolve(root,path)))
  expect(files.length).toBeGreaterThan(90)
  for(const file of files){
   const {descriptor}=parse(readFileSync(file,'utf8'),{filename:file})
   if(!descriptor.template)continue
   const bindings=descriptor.scriptSetup?compileScript(descriptor,{id:file}).bindings:{}
   const template=compileTemplate({source:descriptor.template.content,filename:file,id:file,compilerOptions:{bindingMetadata:bindings}})
   expect(template.errors,`${file} 的模板应可编译`).toEqual([])
   // 编译器已消除局部绑定；剩余标签必须由生产入口的组件注册表解析。
   for(const match of template.code.matchAll(/_resolveComponent\("(a-[a-z0-9-]+)"\)/g)){
    const tag=match[1]!,name=tag.split('-').map(part=>part[0]!.toUpperCase()+part.slice(1)).join('')
    if(!app.component(name))unregistered.push(`${file.slice(root.length)}: ${tag}`)
   }
  }
  expect(unregistered).toEqual([])
 })
})
