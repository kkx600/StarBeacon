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
 const files=['platform/src','collector/src','packages/shared/src'].flatMap(path=>components(resolve(root,path)))
 const app=registerAnt(createApp({}))
 it('双端与共享组件目录均纳入检查',()=>{expect(files.length).toBeGreaterThan(90)})
 // 每个组件独立编译与断言，保留相同单例期限，避免全目录共用一次业务用例预算。
 for(const file of files)it(`组件绑定：${file.slice(root.length)}`,()=>{
  const {descriptor}=parse(readFileSync(file,'utf8'),{filename:file})
  if(!descriptor.template)return
  const bindings=descriptor.scriptSetup?compileScript(descriptor,{id:file}).bindings:{}
  const template=compileTemplate({source:descriptor.template.content,filename:file,id:file,compilerOptions:{bindingMetadata:bindings}})
  expect(template.errors,`${file} 的模板应可编译`).toEqual([])
  const unregistered:string[]=[]
  for(const match of template.code.matchAll(/_resolveComponent\("(a-[a-z0-9-]+)"\)/g)){
   const tag=match[1]!,name=tag.split('-').map(part=>part[0]!.toUpperCase()+part.slice(1)).join('')
   if(!app.component(name))unregistered.push(tag)
  }
  expect(unregistered,`${file.slice(root.length)} 的 Ant 标签应有生产组件绑定`).toEqual([])
 })
})
