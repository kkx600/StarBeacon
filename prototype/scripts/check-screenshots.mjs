import {readFile,writeFile,readdir} from 'node:fs/promises'
import {createHash} from 'node:crypto'
import {renderRoots,digestRenderTree} from './gallery-inputs.mjs'

const root=new URL('../public/screenshots/',import.meta.url)
const themeInputs=['prototype/src/theme.ts','prototype/src/styles.css','web/packages/shared/src/theme.ts','web/packages/shared/src/controls.css']
const layoutInputs=['web/packages/shared/src/navigation.json','web/packages/shared/src/navigation.ts','web/platform/src/navigation.ts','web/platform/src/App.vue','web/packages/shared/src/components/AppShell.vue','web/packages/shared/src/components/NavigationMenu.vue','prototype/src/data/navigation.ts','prototype/src/layouts/ConsoleLayout.vue','prototype/src/router.ts','prototype/src/views/PageView.vue','web/platform/src/features/settings/SettingsWorkspace.vue']
const layoutHash=createHash('sha256')
for(const file of layoutInputs){layoutHash.update(file+'\0');layoutHash.update(await readFile(new URL('../../'+file,import.meta.url)));layoutHash.update('\0')}
const layoutSha256=layoutHash.digest('hex')
const renderTree=await digestRenderTree(new URL('../../',import.meta.url))
const themeHash=createHash('sha256')
for(const file of themeInputs){themeHash.update(file+'\0');themeHash.update(await readFile(new URL('../../'+file,import.meta.url)));themeHash.update('\0')}
const themeSha256=themeHash.digest('hex')
const manifest=JSON.parse(await readFile(new URL('../public/page-manifest.json',import.meta.url),'utf8'))
const log=JSON.parse(await readFile(new URL('capture-log.json',root),'utf8'))
const expected=[...manifest.pages.flatMap(p=>p.states.map(s=>s.image)),...(manifest.collector?.pages??[]).flatMap(p=>p.states.map(s=>s.image)),...[...manifest.boundary,...(manifest.collector?.boundary??[])].map(p=>`boundary/${p.id}.jpg`)]
const refresh=process.argv.includes('--refresh')
const prior=refresh?null:JSON.parse(await readFile(new URL('provenance.json',root),'utf8'))
const entries=[]
const failures=[]

// 只读取 JPEG 头与文件校验值，不改写或处理图片像素。
function dimensions(bytes){
  if(bytes[0]!==0xff||bytes[1]!==0xd8)throw new Error('文件不是 JPEG')
  let offset=2
  while(offset+4<bytes.length){
    if(bytes[offset]!==0xff)throw new Error('JPEG 标记不完整')
    while(bytes[offset]===0xff)offset++
    const marker=bytes[offset++]
    if(marker===0xd9||marker===0xda)break
    if(marker===0x01||(marker>=0xd0&&marker<=0xd7))continue
    const length=bytes.readUInt16BE(offset)
    if(length<2||offset+length>bytes.length)throw new Error('JPEG 段长度无效')
    if([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)){
      return {width:bytes.readUInt16BE(offset+5),height:bytes.readUInt16BE(offset+3)}
    }
    offset+=length
  }
  throw new Error('JPEG 缺少图像尺寸')
}

for(const file of [...new Set([...expected,...log.entries.map(e=>e.file)])]){
  try{
    const source=log.entries.findLast(e=>e.file===file)
    if(!source||!source.stateVerified||source.renderer!=='Codex in-app browser')throw new Error('缺少已核对的浏览器截图来源')
    if(JSON.stringify(source.themeInputs)!==JSON.stringify(themeInputs)||source.themeDigestAlgorithm!=='sha256-path-nul-content-nul'||source.themeSha256!==themeSha256)throw new Error('截图主题与当前全局主题不同，需要从浏览器重新捕获')
    if(JSON.stringify(source.layoutInputs)!==JSON.stringify(layoutInputs)||source.layoutDigestAlgorithm!=='sha256-path-nul-content-nul'||source.layoutSha256!==layoutSha256)throw new Error('截图导航或布局与当前源码不同，需要从浏览器重新捕获')
    if(JSON.stringify(source.renderRoots)!==JSON.stringify(renderRoots)||source.renderTreeSha256!==renderTree.sha256)throw new Error('截图界面源码与当前版本不同，需要从浏览器重新捕获')
    for(const input of source.renderInputs??[]){
      if(typeof input.path!=='string'||input.path.split('/').includes('..')||! /^(prototype\/src|web\/(platform|collector|packages\/shared)\/src)\/[A-Za-z0-9_./-]+$/.test(input.path))throw new Error('截图组件来源路径无效')
      if(createHash('sha256').update(await readFile(new URL('../../'+input.path,import.meta.url))).digest('hex')!==input.sha256)throw new Error('截图组件与当前源码不同，需要从浏览器重新捕获')
    }
    const bytes=await readFile(new URL(file,root))
    const size=dimensions(bytes)
    if(!size.width||!size.height||bytes.length<1000)throw new Error('图像为空或尺寸无效')
    if(size.width!==source.viewport.width)throw new Error(`图片宽度 ${size.width} 与视口 ${source.viewport.width} 不一致`)
    if(size.height<source.viewport.height)throw new Error('图片未覆盖完整视口')
    if(source.viewport.scrollWidth>source.viewport.width)throw new Error('页面存在视口外的横向溢出')
    const sha256=createHash('sha256').update(bytes).digest('hex')
    if(!refresh&&prior?.entries.find(e=>e.file===file)?.sha256!==sha256)throw new Error('文件校验值与来源清单不一致')
    entries.push({...source,bytes:bytes.length,image:size,sha256})
  }catch(error){failures.push({file,error:error.message})}
}

if(log.errors.length)failures.push(...log.errors)
const allFiles=await readdir(root,{recursive:true})
for(const file of allFiles.filter(file=>/\.(?:jpg|jpeg|png|webp)$/i.test(file)))if(!entries.some(entry=>entry.file===file))failures.push({file,error:'图片没有对应来源记录'})
if(failures.length){console.error(JSON.stringify(failures,null,2));process.exit(1)}
if(refresh){
  await writeFile(new URL('provenance.json',root),JSON.stringify({product:'星烽 StarBeacon',synthetic:true,renderer:'Codex in-app browser',renderTreeSha256:renderTree.sha256,layoutSha256,themeSha256,baseStateCount:expected.length,supplementalCount:entries.length-expected.length,entries},null,2)+'\n')
  await writeFile(new URL('provenance-manifest.js',root),`window.StarBeaconGalleryVersions = ${JSON.stringify({renderTreeSha256:renderTree.sha256,images:Object.fromEntries(entries.map(entry=>[entry.file,entry.sha256]))})};\n`)
  await writeFile(new URL('supplemental-manifest.js',root),`window.StarBeaconSupplemental = ${JSON.stringify(entries.filter(entry=>entry.state==='supplemental').map(({file,title})=>({file,title})))};\n`)
}
console.log(`图片核对通过：${expected.length} 张基础状态图，${entries.length-expected.length} 张补充图；JPEG 尺寸、页面横向边界、浏览器来源及 SHA-256 均已核对。`)
