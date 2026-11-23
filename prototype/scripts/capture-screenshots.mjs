import { cp, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'
import { preview } from 'vite'
import { collectorPrototypeScreens } from '../src/data/collectorNavigation.ts'
import { browserManifest, checkGallery, galleryDirectory, galleryFiles, imageExtension, planGallery, viewport } from './screenshot-gallery.mjs'

const prototype = fileURLToPath(new URL('..', import.meta.url))
const replacedMetadata = new Set([
  'capture-log.json', 'provenance.json', 'provenance-manifest.js', 'supplemental-manifest.js',
  'manifest.json', 'manifest.js',
])
const collectorPageIds = new Map(collectorPrototypeScreens.map(screen => [`collector-${screen.view}`, `collector-${screen.page}`]))

async function openState(page, origin, entry, state) {
  const url = new URL(state.url, origin)
  url.searchParams.set('capture', '1')
  const response = await page.goto(url.href, { waitUntil: 'domcontentloaded' })
  if (!response?.ok()) throw new Error(`原型返回 HTTP ${response?.status() ?? '无响应'}`)

  if (entry.group === 'boundary') {
    const title = url.pathname.startsWith('/status/') ? '.status-page .ant-result-title' : '.auth-card h2'
    await page.locator(title).waitFor({ state: 'visible' })
    if (new URL(page.url()).pathname !== url.pathname) throw new Error('边界页面跳转到了其他路由')
  } else {
    const id = collectorPageIds.get(entry.id) ?? entry.id
    const surface = page.locator(`.page-surface[data-page-id="${id}"][data-page-state="${state.state}"]`)
    await surface.waitFor({ state: 'visible' })
    if (entry.group === 'collector') {
      await surface.getByRole('heading', { level: 1, name: entry.title, exact: true }).waitFor({ state: 'visible' })
    }
    if (state.state === 'detail' || state.state === 'action') {
      await page.getByRole('dialog').first().waitFor({ state: 'visible' })
    }
  }
  await page.evaluate(async () => {
    await document.fonts.ready
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))
  })
}

async function capture(manifest, directory) {
  const server = await preview({ root: prototype, preview: { host: '127.0.0.1', port: 0, strictPort: true } })
  try {
    const address = server.httpServer.address()
    if (!address || typeof address === 'string') throw new Error('无法取得原型预览地址')
    const origin = `http://127.0.0.1:${address.port}`
    const executablePath = process.env.STARBEACON_CHROMIUM_EXECUTABLE
    const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : { channel: 'chrome' }) })
    try {
      const page = await browser.newPage({
        viewport, deviceScaleFactor: 1, locale: 'zh-CN', timezoneId: 'Asia/Shanghai', reducedMotion: 'reduce',
      })
      page.setDefaultTimeout(15_000)
      const total = galleryFiles(manifest).size
      let count = 0
      for (const entry of manifest.pages) {
        for (const state of entry.states) {
          try {
            await openState(page, origin, entry, state)
            const destination = join(directory, state.image)
            await mkdir(dirname(destination), { recursive: true })
            await page.screenshot({
              path: destination, type: 'jpeg', quality: 85, scale: 'css', animations: 'disabled', caret: 'hide',
            })
          } catch (error) {
            throw new Error(`重拍失败 ${state.image}（${state.url}）：${error.message}`, { cause: error })
          }
          count++
          if (count % 25 === 0 || count === total) console.log(`已重拍 ${count}/${total} 张`)
        }
      }
      return browser.version()
    } finally {
      await browser.close()
    }
  } finally {
    await server.close()
  }
}

async function main() {
  const catalog = JSON.parse(await readFile(new URL('../public/page-manifest.json', import.meta.url), 'utf8'))
  const manifest = planGallery(catalog, collectorPrototypeScreens)
  galleryFiles(manifest)
  const staging = await mkdtemp(join(prototype, '.screenshots-'))
  const next = join(staging, 'new')
  const previous = join(staging, 'previous')
  let keepBackup = false
  try {
    await cp(galleryDirectory, next, {
      recursive: true,
      verbatimSymlinks: true,
      filter: source => !imageExtension.test(source) && !replacedMetadata.has(relative(galleryDirectory, source)),
    })
    manifest.chromiumVersion = await capture(manifest, next)
    await writeFile(join(next, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
    await writeFile(join(next, 'manifest.js'), browserManifest(manifest))
    const count = await checkGallery(next)
    // 截图和清单核对通过后整批替换。切换失败时恢复原图库。
    await rename(galleryDirectory, previous)
    try {
      await rename(next, galleryDirectory)
    } catch (error) {
      try {
        await rename(previous, galleryDirectory)
      } catch (restoreError) {
        keepBackup = true
        throw new AggregateError([error, restoreError], `图库切换和恢复失败，原图库位于 ${previous}`)
      }
      throw error
    }
    console.log(`重拍完成，${count} 张 ${viewport.width}×${viewport.height} JPEG，Chromium ${manifest.chromiumVersion}。`)
  } finally {
    if (!keepBackup) await rm(staging, { recursive: true, force: true })
  }
}

await main()
