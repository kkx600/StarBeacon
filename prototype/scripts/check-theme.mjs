import {readFile} from 'node:fs/promises'
import {palette} from '../src/theme.ts'

// 正文、状态、焦点与图形分别校验；浅色轮廓与占位提示独立记录，不声明全界面 AA 合规。
function luminance(hex) {
  const channels = hex.slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
  const linear = channels.map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722
}
function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a)
  return (values[0] + 0.05) / (values[1] + 0.05)
}
const textPairs = [
  ['surface', 'primary'],
  ...['surface', 'workspace', 'tableHeader', 'rowHover', 'navSelected', 'tabSelected', 'infoSurface'].flatMap(background => ['text', 'muted', 'link'].map(foreground => [foreground, background])),
  ...['syntaxVariable','syntaxOption','syntaxNumber'].flatMap(foreground=>['surface','tableHeader'].map(background=>[foreground,background])),
  ['fieldLabel', 'tableHeader'], ['recordText', 'surface'],
  ['success', 'successSurface'], ['warning', 'warningSurface'], ['danger', 'dangerSurface'],
  ['infoText', 'infoSurface'], ['statusText', 'statusSurface'], ['selectionText', 'selectionSurface'],
  ...['screenWorkspace', 'screenPanel', 'screenMetric'].flatMap(background => ['screenText', 'screenMuted', 'screenNumber', 'screenLink', 'screenAmber', 'screenDanger'].map(foreground => [foreground, background])),
]
const graphicPairs = [
  ['selectionBorder', 'surface'], ['selectionBorder', 'workspace'], ['primary', 'surface'], ['primary', 'workspace'],
  ['action', 'surface'], ['action', 'workspace'],
  ['successDot', 'successSurface'], ['warningDot', 'warningSurface'], ['dangerDot', 'dangerSurface'],
  ...['primary', 'teal', 'violet', 'chartOrange', 'chartNeutral'].map(foreground => [foreground, 'surface']),
  ...['screenBlue', 'screenTeal', 'screenViolet', 'screenAmber'].map(foreground => [foreground, 'screenPanel']),
]
const failures = []
for (const [pairs, minimum] of [[textPairs, 4.5], [graphicPairs, 3]]) {
  for (const [foreground, background] of pairs) {
    const ratio = contrast(palette[foreground], palette[background])
    if (ratio < minimum) failures.push(`${foreground} / ${background}: ${ratio.toFixed(2)} < ${minimum}`)
  }
}
const gallery = await readFile(new URL('../public/screenshots/index.html', import.meta.url), 'utf8')
for (const key of ['primary', 'action', 'link', 'workspace', 'text', 'muted', 'line', 'controlBorder', 'infoSurface']) {
  const property = '--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase())
  if (!gallery.includes(`${property}:${palette[key]}`)) failures.push(`截图目录配色不一致：${property}`)
}
if (failures.length) {
  console.error(failures.join('\n'))
  process.exit(1)
}
console.log(`配色核对通过：${textPairs.length} 组正文与业务文字对比度 ≥ 4.5，${graphicPairs.length} 组选择标记、焦点与图形对比度 ≥ 3，截图目录语义色一致。`)
console.log(`参考样式实测（不计入正文 AA 范围）：主按钮白字 ${contrast(palette.surface, palette.action).toFixed(2)}:1，占位提示 ${contrast(palette.textPlaceholder, palette.surface).toFixed(2)}:1，普通输入框轮廓 ${contrast(palette.controlBorder, palette.surface).toFixed(2)}:1。`)
