import {test} from 'node:test'
import assert from 'node:assert/strict'
import {mkdtemp, mkdir, readFile, writeFile, copyFile, appendFile, rm} from 'node:fs/promises'
import {tmpdir} from 'node:os'
import {dirname, join} from 'node:path'
import {fileURLToPath,pathToFileURL} from 'node:url'
import {spawnSync} from 'node:child_process'
import {createHash} from 'node:crypto'
import {renderRoots,digestRenderTree} from './gallery-inputs.mjs'

const project = fileURLToPath(new URL('../../', import.meta.url))
const themeInputs = ['prototype/src/theme.ts', 'prototype/src/styles.css', 'web/packages/shared/src/theme.ts', 'web/packages/shared/src/controls.css']
const layoutInputs=['web/packages/shared/src/navigation.json','web/packages/shared/src/navigation.ts','web/platform/src/navigation.ts','web/platform/src/App.vue','web/packages/shared/src/components/AppShell.vue','web/packages/shared/src/components/NavigationMenu.vue','prototype/src/data/navigation.ts','prototype/src/layouts/ConsoleLayout.vue','prototype/src/router.ts','prototype/src/views/PageView.vue','web/platform/src/features/settings/SettingsWorkspace.vue']

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'starbeacon-gallery-'))
  try {
    const source = join(project, 'prototype/public/screenshots')
    const gallery = join(root, 'prototype/public/screenshots')
    const original = JSON.parse(await readFile(join(source, 'provenance.json'), 'utf8')).entries.find(row => row.state === 'data')
    const entry = structuredClone(original)
    for (const file of [...new Set([...themeInputs,...layoutInputs,...(entry.renderInputs??[]).map(input=>input.path), 'prototype/scripts/check-screenshots.mjs','prototype/scripts/gallery-inputs.mjs'])]) {
      const target = join(root, file)
      await mkdir(dirname(target), {recursive: true})
      await copyFile(join(project, file), target)
    }
    await mkdir(dirname(join(gallery, entry.file)), {recursive: true})
    await copyFile(join(source, entry.file), join(gallery, entry.file))
    // 元数据逻辑使用隔离夹具，不能当作当前真实页面的视觉验收。
    const digest=async paths=>{
      const hash=createHash('sha256')
      for(const file of paths){hash.update(file+'\0');hash.update(await readFile(join(root,file)));hash.update('\0')}
      return hash.digest('hex')
    }
    entry.themeSha256=await digest(themeInputs)
    entry.layoutSha256=await digest(layoutInputs)
    for(const input of entry.renderInputs??[])input.sha256=createHash('sha256').update(await readFile(join(root,input.path))).digest('hex')
    entry.renderRoots=renderRoots
    entry.renderTreeSha256=(await digestRenderTree(pathToFileURL(root+'/'))).sha256
    await writeFile(join(gallery, '../page-manifest.json'), JSON.stringify({pages: [{id:entry.viewport.page,states: [{state:entry.viewport.state,image: entry.file}]}], boundary: []}))
    await writeFile(join(gallery, 'capture-log.json'), JSON.stringify({entries: [entry], errors: []}))
    await writeFile(join(gallery, 'provenance.json'), JSON.stringify({entries: [entry]}))
    const check = (...args) => spawnSync(process.execPath, [join(root, 'prototype/scripts/check-screenshots.mjs'), ...args], {encoding: 'utf8', timeout: 15000})
    await run({root, gallery, entry, check})
  } finally {
    await rm(root, {recursive: true, force: true})
  }
}

test('当前主题的真实浏览器来源与 JPEG 可以通过严格检查', async () => fixture(async ({check}) => {
  const result = check()
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /1 张基础状态图，0 张补充图/)
}))

test('主题改变后，即使刷新清单也不能把旧图标记为当前截图', async () => fixture(async ({root, check}) => {
  const file = join(root, 'web/packages/shared/src/theme.ts')
  await writeFile(file, (await readFile(file, 'utf8')).replace('#5d87ff', '#5d87fe'))
  const result = check('--refresh')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /截图主题与当前全局主题不同/)
}))

test('导航变化后，刷新清单不能将旧布局声明为当前截图',async()=>fixture(async({root,check})=>{
  const file=join(root,'web/packages/shared/src/navigation.json')
  await appendFile(file,'\n')
  const result=check('--refresh')
  assert.equal(result.status,1)
  assert.match(result.stderr,/截图导航或布局与当前源码不同/)
}))

test('工程组件发生变化时，未改变主题也必须重新捕获原型',async()=>fixture(async({root,check})=>{
  await writeFile(join(root,'web/platform/src/unrecorded-component.ts'),'export const label="当前界面"\n')
  const result=check('--refresh')
  assert.equal(result.status,1)
  assert.match(result.stderr,/截图界面源码与当前版本不同/)
}))

test('主题未变时，图片字节变化仍被原有 SHA-256 检查拒绝', async () => fixture(async ({gallery, entry, check}) => {
  await appendFile(join(gallery, entry.file), '\n')
  const result = check()
  assert.equal(result.status, 1)
  assert.match(result.stderr, /文件校验值与来源清单不一致/)
}))

test('缺少浏览器核对来源时，刷新清单不能放宽原有检查', async () => fixture(async ({gallery, entry, check}) => {
  await writeFile(join(gallery, 'capture-log.json'), JSON.stringify({entries: [{...entry, stateVerified: false}], errors: []}))
  const result = check('--refresh')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /缺少已核对的浏览器截图来源/)
}))

test('采集器界面源码变化后，即使刷新清单也不能接受原截图', async () => fixture(async ({root, gallery, entry, check}) => {
  const path = 'web/collector/src/features/network/ResponseConfiguration.vue'
  const target = join(root, path)
  await mkdir(dirname(target), {recursive: true})
  await copyFile(join(project, path), target)
  const {createHash} = await import('node:crypto')
  entry.renderInputs = [...(entry.renderInputs ?? []).filter(input => input.path !== path), {path, sha256: createHash('sha256').update(await readFile(target)).digest('hex')}]
  await writeFile(join(gallery, 'capture-log.json'), JSON.stringify({entries: [entry], errors: []}))
  assert.equal(check().status, 0)
  await appendFile(target, '\n')
  const result = check('--refresh')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /截图界面源码与当前版本不同/)
}))

test('未单独列出的采集器组件同样属于截图来源',async()=>fixture(async({root,check})=>{
 await writeFile(join(root,'web/collector/src/unrecorded-component.ts'),'export const label="采集状态"\n')
 const result=check('--refresh')
 assert.equal(result.status,1)
 assert.match(result.stderr,/截图界面源码与当前版本不同/)
}))

test('页面已导航但观测仍属于上一页时不能登记为当前截图',async()=>fixture(async({gallery,entry,check})=>{
 entry.viewport.page='another-page'
 await writeFile(join(gallery,'capture-log.json'),JSON.stringify({entries:[entry],errors:[]}))
 const result=check('--refresh')
 assert.equal(result.status,1)
 assert.match(result.stderr,/截图可见页面或状态与页面目录不同/)
}))

test('边界截图不得沿用上一业务页面的观测',async()=>fixture(async({gallery,entry,check})=>{
 const file='boundary/auth-login.jpg'
 await mkdir(join(gallery,'boundary'),{recursive:true})
 await copyFile(join(gallery,entry.file),join(gallery,file))
 await rm(join(gallery,entry.file))
 entry.file=file;entry.state='boundary';entry.url='http://127.0.0.1:4173/auth/login'
 await writeFile(join(gallery,'../page-manifest.json'),JSON.stringify({pages:[],boundary:[{id:'auth-login',url:'/auth/login'}]}))
 await writeFile(join(gallery,'capture-log.json'),JSON.stringify({entries:[entry],errors:[]}))
 const result=check('--refresh')
 assert.equal(result.status,1)
 assert.match(result.stderr,/边界截图仍停留在业务页面或错误路由/)
}))

test('组件来源不得通过父目录或工程目录外路径绕过核对', async () => fixture(async ({gallery, entry, check}) => {
  entry.renderInputs = [{path: 'web/collector/src/../../../secret.json', sha256: '0'.repeat(64)}]
  await writeFile(join(gallery, 'capture-log.json'), JSON.stringify({entries: [entry], errors: []}))
  const result = check('--refresh')
  assert.equal(result.status, 1)
  assert.match(result.stderr, /截图组件来源路径无效/)
}))


test('备用浏览器的原生截图保留同等来源与当前源码核验',async()=>fixture(async({gallery,entry,check})=>{
 entry.renderer='Chrome DevTools MCP';entry.captureMethod='chrome-devtools-mcp-native'
 await writeFile(join(gallery,'capture-log.json'),JSON.stringify({entries:[entry],errors:[]}))
 assert.equal(check().status,0)
 delete entry.captureMethod
 await writeFile(join(gallery,'capture-log.json'),JSON.stringify({entries:[entry],errors:[]}))
 assert.equal(check('--refresh').status,1)
}))
