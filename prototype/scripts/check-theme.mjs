import { readFile, readdir } from 'node:fs/promises';
import { theme } from 'ant-design-vue';
import {
  appTheme,
  componentColors,
  componentSeeds,
  componentSurfaces,
  palette,
  screenChartColorKeys,
  screenChartPalette,
} from '../src/theme.ts';

// 文字类颜色（含按钮白字、链接、语义标签）按 4.5:1 强制核对；控件轮廓与占位提示只记录实测值。
function linearRgb(hex) {
  const channels = hex
    .slice(1)
    .match(/../g)
    .map(value => parseInt(value, 16) / 255);
  return channels.map(value => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
}
function luminance(hex) {
  const linear = linearRgb(hex);
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
}
function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

// Machado 学位论文表 A.1 的 1.0 强度矩阵，输入为线性 sRGB。
const visionMatrices = {
  红色觉缺失: [
    [0.152, 1.053, -0.205],
    [0.115, 0.786, 0.099],
    [-0.004, -0.048, 1.052],
  ],
  绿色觉缺失: [
    [0.367, 0.861, -0.228],
    [0.28, 0.673, 0.047],
    [-0.012, 0.043, 0.969],
  ],
};
const linearToLms = [
  [0.4122214708, 0.5363325363, 0.0514459929],
  [0.2119034982, 0.6806995451, 0.1073969566],
  [0.0883024619, 0.2817188376, 0.6299787005],
];
const lmsToOklab = [
  [0.2104542553, 0.793617785, -0.0040720468],
  [1.9779984951, -2.428592205, 0.4505937099],
  [0.0259040371, 0.7827717662, -0.808675766],
];
function multiply(matrix, channels) {
  return matrix.map(row => row.reduce((sum, coefficient, index) => sum + coefficient * channels[index], 0));
}
function oklab(channels) {
  return multiply(lmsToOklab, multiply(linearToLms, channels).map(Math.cbrt));
}

const failures = [];
const derived = { ...theme.defaultAlgorithm({ ...theme.defaultSeed, ...appTheme.token }), ...appTheme.token };
const expectedSeeds = {
  colorPrimary: '#2f54eb',
  colorSuccess: '#3a9e50',
  colorWarning: '#e08a00',
  colorError: '#e5484d',
  colorInfo: '#2f54eb',
};
for (const [key, value] of Object.entries(expectedSeeds)) {
  if (componentSeeds[key] !== value || derived[key] !== value) failures.push(`组件基础色与设计规范不一致：${key}`);
}
// 提示表面由主题显式指定：信息提示为纯灰，其余与业务标签共用浅底。
for (const [key, expected] of Object.entries({
  colorInfoBg: '#fafafa',
  colorInfoBorder: '#e5e5e5',
  colorSuccessBg: '#ecf8ee',
  colorWarningBg: '#fff4dc',
  colorErrorBg: '#fdeceb',
})) {
  if (derived[key] !== expected || componentSurfaces[key] !== expected)
    failures.push(`提示表面与设计规范不一致：${key}`);
}
if (componentColors.colorPrimary !== expectedSeeds.colorPrimary) failures.push('算法派生主色与基础色不一致');
for (const [key, token] of Object.entries({
  primary: 'colorPrimary',
  primaryHover: 'colorPrimaryHover',
  primaryActive: 'colorPrimaryActive',
  action: 'colorPrimary',
  actionHover: 'colorPrimaryHover',
  actionActive: 'colorPrimaryActive',
  link: 'colorLink',
  successSurface: 'colorSuccessBg',
  warningSurface: 'colorWarningBg',
  dangerSurface: 'colorErrorBg',
  infoSurface: 'colorInfoBg',
  warningBorder: 'colorWarningBorder',
  selectionSurface: 'colorPrimaryBg',
  selectionText: 'colorPrimaryTextActive',
})) {
  if (palette[key] !== derived[token]) failures.push(`业务颜色与组件派生色不一致：${key}`);
}
for (const name of [
  'Button',
  'Input',
  'InputNumber',
  'Select',
  'DatePicker',
  'TimePicker',
  'Checkbox',
  'Radio',
  'Alert',
  'Tag',
  'Switch',
  'Tabs',
]) {
  if (Object.keys(appTheme.components?.[name] ?? {}).some(key => /color/i.test(key)))
    failures.push(`控件单独覆盖组件颜色：${name}`);
}
if (
  palette.workspace !== '#f4f4f4' ||
  palette.surface !== '#ffffff' ||
  appTheme.token.colorBgLayout !== palette.workspace ||
  appTheme.token.colorBgContainer !== palette.surface
)
  failures.push('白色面板或浅灰工作区发生偏移');

const textPairs = [
  ...[
    'surface',
    'workspace',
    'tableHeader',
    'rowHover',
    'navSelected',
    'tabSelected',
    'infoSurface',
    'successSurface',
    'warningSurface',
    'dangerSurface',
  ].flatMap(background => ['text', 'muted'].map(foreground => [foreground, background])),
  ...['syntaxVariable', 'syntaxOption', 'syntaxNumber', 'syntaxKeyword', 'syntaxString'].flatMap(foreground =>
    ['surface', 'tableHeader'].map(background => [foreground, background]),
  ),
  ['fieldLabel', 'tableHeader'],
  ['recordText', 'surface'],
  ['danger', 'dangerSurface'],
  ['infoText', 'infoSurface'],
  ['statusText', 'statusSurface'],
  ['selectionText', 'selectionSurface'],
  // 主色文字、按钮白字与语义标签属于强制项。
  ['surface', 'action'],
  ['link', 'surface'],
  ['link', 'tableHeader'],
  ['link', 'navSelected'],
  ['link', 'tabSelected'],
  ['link', 'workspace'],
  ['success', 'successSurface'],
  ['success', 'surface'],
  ['warning', 'warningSurface'],
  ['warning', 'surface'],
  ['danger', 'surface'],
  ['criticalText', 'critical'],
  ['progressText', 'progressSurface'],
  ...['screenWorkspace', 'screenPanel', 'screenMetric'].flatMap(background =>
    ['screenText', 'screenMuted', 'screenNumber', 'screenLink', 'screenAmber', 'screenDanger'].map(foreground => [
      foreground,
      background,
    ]),
  ),
];
const graphicPairs = [
  ...['primary', 'teal', 'violet', 'chartOrange', 'chartNeutral'].map(foreground => [foreground, 'surface']),
  ...screenChartColorKeys.map(foreground => [foreground, 'screenPanel']),
];
for (const [pairs, minimum] of [
  [textPairs, 4.5],
  [graphicPairs, 3],
]) {
  for (const [foreground, background] of pairs) {
    const ratio = contrast(palette[foreground], palette[background]);
    if (ratio < minimum) failures.push(`${foreground} / ${background}: ${ratio.toFixed(2)} < ${minimum}`);
  }
}

const minimumDistance = 0.08;
const seriesRgb = screenChartPalette.map(linearRgb);
const visionDistances = Object.entries(visionMatrices).map(([label, matrix]) => {
  const colors = seriesRgb.map(rgb => oklab(multiply(matrix, rgb).map(value => Math.max(0, Math.min(1, value)))));
  const distances = colors.map((color, index) => {
    const next = (index + 1) % colors.length;
    const distance = Math.hypot(...color.map((channel, component) => channel - colors[next][component]));
    if (distance < minimumDistance)
      failures.push(
        `${label} ${screenChartColorKeys[index]} / ${screenChartColorKeys[next]}：色差 ${distance.toFixed(3)} < ${minimumDistance}`,
      );
    return distance;
  });
  return [label, Math.min(...distances)];
});

// 同时扫描三个入口，防止局部样式遮蔽提示底色或使用不存在的语义变量。
const root = new URL('../../', import.meta.url);
const files = [];
for (const dir of ['web/platform/src', 'web/collector/src', 'web/packages/shared/src', 'prototype/src']) {
  for (const name of await readdir(new URL(dir, root), { recursive: true })) {
    if (/\.(?:vue|ts|css)$/.test(name))
      files.push({ file: `${dir}/${name}`, source: await readFile(new URL(`${dir}/${name}`, root), 'utf8') });
  }
}
const variables = new Set(
  Object.keys(palette).map(key => '--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase())),
);
for (const { source } of files) for (const match of source.matchAll(/(--[\w-]+)\s*:/g)) variables.add(match[1]);
for (const { file, source } of files) {
  for (const match of source.matchAll(/var\(\s*(--[\w-]+)/g))
    if (!variables.has(match[1])) failures.push(`未定义的颜色或布局变量：${file} ${match[1]}`);
  if (file.endsWith('/theme.ts')) continue;
  if (/(?:#[\da-f]{3,8}\b|rgba?\([\d\s,.%/]+\))/i.test(source)) failures.push(`局部文件存在独立颜色常量：${file}`);
  if (/\.ant-alert[^{}]*\{[^}]*\b(?:background|border-color|color)\s*:/s.test(source))
    failures.push(`局部样式覆盖提示语义色：${file}`);
  if (
    /\bmessage\.(?:info|success|warning|error|open|loading)\(/.test(source) &&
    !source.includes('useFeedback') &&
    !source.includes('antMessage.useMessage()')
  )
    failures.push(`消息提示未继承组件主题：${file}`);
}
const gallery = await readFile(new URL('../public/screenshots/index.html', import.meta.url), 'utf8');
for (const key of [
  'primary',
  'action',
  'link',
  'workspace',
  'text',
  'muted',
  'line',
  'controlBorder',
  'infoSurface',
  'selectionSurface',
  'selectionText',
]) {
  const property = '--' + key.replace(/[A-Z]/g, letter => '-' + letter.toLowerCase());
  const declaration = new RegExp(`(?:^|[;{])\\s*${property}\\s*:\\s*${palette[key]}\\s*(?:[;}]|$)`, 'm');
  if (!declaration.test(gallery)) failures.push(`截图目录配色不一致：${property}`);
}
if (failures.length) {
  console.error(failures.join('\n'));
  process.exit(1);
}
console.log(
  `配色核对通过：${files.length} 个源码文件、5 项基础色、提示表面、控件默认状态、根级变量、消息主题与图库配色一致。`,
);
console.log(`正文与业务文字 ${textPairs.length} 组 ≥ 4.5:1，图表 ${graphicPairs.length} 组 ≥ 3:1。`);
console.log(`大屏系列明度：${seriesRgb.map(rgb => oklab(rgb)[0].toFixed(3)).join('／')}（Oklab L）。`);
const screenContrast = Math.min(...screenChartPalette.map(color => contrast(color, palette.screenPanel)));
console.log(`大屏系列与面板的最小对比度 ${screenContrast.toFixed(2)}:1。`);
for (const [label, distance] of visionDistances)
  console.log(`${label}模拟相邻系列最小 Oklab 色差 ${distance.toFixed(3)} ≥ ${minimumDistance}。`);
for (const [label, foreground, background] of [
  ['占位提示', 'textPlaceholder', 'surface'],
  ['输入框轮廓', 'controlBorder', 'surface'],
  ['面板与工作区', 'surface', 'workspace'],
])
  console.log(
    `非文字项实测（不设门槛）：${label} ${contrast(palette[foreground], palette[background]).toFixed(2)}:1。`,
  );
