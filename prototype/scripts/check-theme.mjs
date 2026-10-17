import {readFile, readdir} from 'node:fs/promises'
import {theme} from 'ant-design-vue'
import {appTheme, componentColors, componentSeeds, palette} from '../src/theme.ts'

// 正文对比度与参考组件配色分开核对；不把浅色轮廓和品牌色宣称为全界面 AA。
function luminance(hex) {
  const channels = hex.slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
  const linear = channels.map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
}
function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a)
  return (values[0] + 0.05) / (values[1] + 0.05)
}
const failures = []
const derived = {...theme.defaultAlgorithm({...theme.defaultSeed, ...appTheme.token}), ...appTheme.token}
const expectedSeeds = {colorPrimary: '#5d87ff', colorSuccess: '#60c041', colorWarning: '#f9901f', colorError: '#e13c39', colorInfo: '#38c0fc'}
for (const [key, value] of Object.entries(expectedSeeds)) {
  if (componentSeeds[key] !== value || derived[key] !== value) failures.push(`组件基础色与参考方案不一致：${key}`)
}
for (const [key, expected] of Object.entries({colorSuccessBg: '#f6fff0', colorWarningBg: '#fff9eb', colorErrorBg: '#fff3f0', colorInfoBg: '#f0fdff'})) {
  if (derived[key] !== expected || componentColors[key] !== expected) failures.push(`组件库派生提示底色不一致：${key}`)
}
for (const [key, token] of Object.entries({primary: 'colorPrimary', primaryHover: 'colorPrimaryHover', primaryActive: 'colorPrimaryActive', action: 'colorPrimary', actionHover: 'colorPrimaryHover', actionActive: 'colorPrimaryActive', link: 'colorLink', successSurface: 'colorSuccessBg', warningSurface: 'colorWarningBg', dangerSurface: 'colorErrorBg', infoSurface: 'colorInfoBg', warningBorder: 'colorWarningBorder', selectionSurface: 'colorPrimaryBg', selectionText: 'colorPrimaryTextActive'})) {
  if (palette[key] !== derived[token]) failures.push(`业务颜色与组件派生色不一致：${key}`)
}
for (const name of ['Button', 'Input', 'InputNumber', 'Select', 'DatePicker', 'TimePicker', 'Checkbox', 'Radio', 'Alert', 'Tag', 'Switch', 'Tabs']) {
  if (Object.keys(appTheme.components?.[name] ?? {}).some(key => /color/i.test(key))) failures.push(`控件单独覆盖组件颜色：${name}`)
}
if (palette.workspace !== '#f7f7f7' || palette.surface !== '#ffffff' || appTheme.token.colorBgLayout !== palette.workspace || appTheme.token.colorBgContainer !== palette.surface) failures.push('白色面板或浅灰工作区发生偏移')

const textPairs = [
  ...['surface', 'workspace', 'tableHeader', 'rowHover', 'navSelected', 'tabSelected', 'infoSurface', 'successSurface', 'warningSurface', 'dangerSurface'].flatMap(background => ['text', 'muted'].map(foreground => [foreground, background])),
  ...['syntaxVariable', 'syntaxOption', 'syntaxNumber', 'syntaxKeyword', 'syntaxString'].flatMap(foreground => ['surface', 'tableHeader'].map(background => [foreground, background])),
  ['fieldLabel', 'tableHeader'], ['recordText', 'surface'], ['danger', 'dangerSurface'], ['infoText', 'infoSurface'], ['statusText', 'statusSurface'], ['selectionText', 'selectionSurface'],
  ...['screenWorkspace', 'screenPanel', 'screenMetric'].flatMap(background => ['screenText', 'screenMuted', 'screenNumber', 'screenLink', 'screenAmber', 'screenDanger'].map(foreground => [foreground, background])),
]
const graphicPairs = [
  ...['primary', 'teal', 'violet', 'chartOrange', 'chartNeutral'].map(foreground => [foreground, 'surface']),
  ...['screenBlue', 'screenTeal', 'screenViolet', 'screenAmber'].map(foreground => [foreground, 'screenPanel']),
]
for (const [pairs, minimum] of [[textPairs, 4.5], [graphicPairs, 3]]) {
  for (const [foreground, background] of pairs) {
    const ratio = contrast(palette[foreground], palette[background])
    if (ratio < minimum) failures.push(`${foreground} / ${background}: ${ratio.toFixed(2)} < ${minimum}`)
  }
}

// 同时扫描三个入口，防止局部样式遮蔽提示底色或使用不存在的语义变量。
const root = new URL('../../', import.meta.url)
const files = []
for (const dir of ['web/platform/src', 'web/collector/src', 'web/packages/shared/src', 'prototype/src']) {
  for (const name of await readdir(new URL(dir, root), {recursive: true})) {
    if (/\.(?:vue|ts|css)$/.test(name)) files.push({file: `${dir}/${name}`, source: await readFile(new URL(`${dir}/${name}`, root), 'utf8')})
  }
}
const variables = new Set(Object.keys(palette).map(key => '--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase())))
for (const {source} of files) for (const match of source.matchAll(/(--[\w-]+)\s*:/g)) variables.add(match[1])
for (const {file, source} of files) {
  for (const match of source.matchAll(/var\(\s*(--[\w-]+)/g)) if (!variables.has(match[1])) failures.push(`未定义的颜色或布局变量：${file} ${match[1]}`)
  if (file.endsWith('/theme.ts')) continue
  if (/(?:#[\da-f]{3,8}\b|rgba?\([\d\s,.%/]+\))/i.test(source)) failures.push(`局部文件存在独立颜色常量：${file}`)
  if (/\.ant-alert[^{}]*\{[^}]*\b(?:background|border-color|color)\s*:/s.test(source)) failures.push(`局部样式覆盖提示语义色：${file}`)
  if (/\bmessage\.(?:info|success|warning|error|open|loading)\(/.test(source) && !source.includes('useFeedback') && !source.includes('antMessage.useMessage()')) failures.push(`消息提示未继承组件主题：${file}`)
}
const gallery = await readFile(new URL('../public/screenshots/index.html', import.meta.url), 'utf8')
for (const key of ['primary', 'action', 'link', 'workspace', 'text', 'muted', 'line', 'controlBorder', 'infoSurface', 'selectionSurface', 'selectionText']) {
  const property = '--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase())
  if (!gallery.includes(`${property}:${palette[key]}`)) failures.push(`截图目录配色不一致：${property}`)
}
if (failures.length) {
  console.error(failures.join('\n'))
  process.exit(1)
}
console.log(`配色核对通过：${files.length} 个源码文件、5 项基础色、4 类提示派生底色、控件默认状态、根级变量、消息主题与图库配色一致。`)
console.log(`正文与业务文字 ${textPairs.length} 组 ≥ 4.5:1，图表 ${graphicPairs.length} 组 ≥ 3:1。`)
for (const [label, foreground, background] of [['主按钮白字', 'surface', 'action'], ['正文链接', 'link', 'surface'], ['占位提示', 'textPlaceholder', 'surface'], ['输入框轮廓', 'controlBorder', 'surface'], ['成功状态', 'success', 'successSurface'], ['关注状态', 'warning', 'warningSurface']]) console.log(`参考组件实测（不声明 AA）：${label} ${contrast(palette[foreground], palette[background]).toFixed(2)}:1。`)
