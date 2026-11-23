import { readFile, readdir } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const galleryDirectory = fileURLToPath(new URL('../public/screenshots', import.meta.url));
export const viewport = { width: 1440, height: 900 };
export const imageExtension = /\.(?:jpe?g|png|webp|avif|gif|svg|bmp)$/i;

const representativePages = new Map([
  ['table', 'alerts'],
  ['search', 'search'],
  ['overview', 'overview'],
  ['topology', 'topology'],
  ['playbook', 'playbooks'],
  ['chat', 'chat'],
  ['rule-studio', 'rule-studio'],
  ['retention', 'retention'],
  ['screen', 'big-screen'],
]);
const businessStates = new Set(['data', 'empty', 'loading', 'error', 'detail', 'action']);
const identifier = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const imagePath = /^(?:[a-z0-9-]+\/){1,2}[a-z0-9-]+\.jpg$/;
const frameMarkers = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

export function planGallery(catalog, collectorScreens) {
  for (const [kind, id] of representativePages) {
    if (!catalog.pages.some(page => page.id === id && page.kind === kind)) {
      throw new Error(`找不到代表页面 ${id}（${kind}）`);
    }
  }

  const groups = [
    ...catalog.groups.map(({ id, title }) => ({ id, title })),
    { id: 'collector', title: catalog.collector.title },
    { id: 'boundary', title: '登录与访问边界' },
  ];
  const pages = catalog.pages.map(({ id, title, group, kind, description, requirements, states }) => {
    const required = representativePages.get(kind) === id ? businessStates : new Set(['data']);
    const selected = states.filter(item => required.has(item.state));
    if (selected.length !== required.size || new Set(selected.map(item => item.state)).size !== required.size) {
      throw new Error(`页面 ${id} 缺少需要重拍的状态或状态重复`);
    }
    return { id, title, group, description, requirements, states: selected };
  });
  const collector = collectorScreens.map(({ view, path, page, title, description }) => ({
    id: `collector-${view}`,
    title,
    group: 'collector',
    description,
    requirements: catalog.collector.pages.find(item => item.id === `collector-${page}`)?.requirements ?? [],
    states: [{ state: 'data', title: '有数据', url: `${path}?state=data`, image: `collector/${view}/data.jpg` }],
  }));
  const boundary = [...catalog.boundary, ...catalog.collector.boundary].map(({ id, title, url }) => ({
    id,
    title,
    group: 'boundary',
    states: [{ state: 'boundary', title: '访问边界', url, image: `boundary/${id}.jpg` }],
  }));
  return { version: 1, viewport, groups, pages: [...pages, ...collector, ...boundary] };
}

export function browserManifest(manifest) {
  return `window.StarBeaconScreenshotManifest = ${JSON.stringify(manifest)};\n`;
}

export function galleryFiles(manifest) {
  if (
    manifest?.version !== 1 ||
    manifest.viewport?.width !== viewport.width ||
    manifest.viewport?.height !== viewport.height
  ) {
    throw new Error(`截图清单版本或视口无效，要求 ${viewport.width}×${viewport.height}`);
  }
  if (!Array.isArray(manifest.groups) || !Array.isArray(manifest.pages) || !manifest.pages.length) {
    throw new Error('截图清单缺少模块或页面');
  }

  const groups = new Set();
  for (const { id, title } of manifest.groups) {
    if (typeof id !== 'string' || !identifier.test(id) || !title || groups.has(id)) {
      throw new Error(`截图模块无效或重复：${id}`);
    }
    groups.add(id);
  }
  const pages = new Set();
  const files = new Set();
  for (const { id, title, group, states } of manifest.pages) {
    if (
      typeof id !== 'string' ||
      !identifier.test(id) ||
      !title ||
      !groups.has(group) ||
      pages.has(id) ||
      !Array.isArray(states) ||
      !states.length
    ) {
      throw new Error(`截图页面无效或重复：${id}`);
    }
    pages.add(id);
    const requiredState = group === 'boundary' ? 'boundary' : 'data';
    const selected = new Set();
    for (const { image, state, title, url } of states) {
      if (
        typeof image !== 'string' ||
        !imagePath.test(image) ||
        !title ||
        typeof url !== 'string' ||
        !/^\/(?![\/\\])/.test(url)
      ) {
        throw new Error(`截图路径或链接无效：${id}／${image}`);
      }
      if ((group === 'boundary' ? state !== 'boundary' : !businessStates.has(state)) || selected.has(state)) {
        throw new Error(`截图状态无效或重复：${id}／${state}`);
      }
      if (files.has(image)) throw new Error(`截图清单重复登记：${image}`);
      selected.add(state);
      files.add(image);
    }
    if (!selected.has(requiredState)) throw new Error(`截图页面缺少 ${requiredState} 状态：${id}`);
  }
  return files;
}

function dimensions(bytes) {
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8 || bytes.at(-2) !== 0xff || bytes.at(-1) !== 0xd9) {
    throw new Error('JPEG 文件头或结束标记无效');
  }
  let offset = 2;
  while (offset + 4 < bytes.length) {
    if (bytes[offset] !== 0xff) throw new Error('JPEG 标记不完整');
    while (bytes[offset] === 0xff) offset++;
    const marker = bytes[offset++];
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 2 > bytes.length) throw new Error('JPEG 段长度无效');
    const length = bytes.readUInt16BE(offset);
    if (length < 2 || offset + length > bytes.length) throw new Error('JPEG 段长度无效');
    if (frameMarkers.has(marker)) {
      if (length < 8) throw new Error('JPEG 尺寸段不完整');
      return { width: bytes.readUInt16BE(offset + 5), height: bytes.readUInt16BE(offset + 3) };
    }
    offset += length;
  }
  throw new Error('JPEG 缺少图像尺寸');
}

export async function checkGallery(directory) {
  const manifest = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8'));
  const expected = galleryFiles(manifest);
  const sidecar = await readFile(join(directory, 'manifest.js'), 'utf8');
  if (sidecar !== browserManifest(manifest)) throw new Error('浏览器清单 manifest.js 与 manifest.json 不一致');

  const actual = new Set();
  for (const entry of await readdir(directory, { recursive: true, withFileTypes: true })) {
    if (entry.isFile() && imageExtension.test(entry.name)) {
      actual.add(relative(directory, join(entry.parentPath, entry.name)).split(sep).join('/'));
    }
  }
  const failures = [];
  for (const file of actual) {
    if (!expected.has(file)) failures.push(`${file} 未登记到截图清单`);
  }
  for (const file of expected) {
    if (!actual.has(file)) {
      failures.push(`${file} 缺少截图文件`);
      continue;
    }
    try {
      const { width, height } = dimensions(await readFile(join(directory, file)));
      if (width !== viewport.width || height !== viewport.height) {
        throw new Error(`尺寸为 ${width}×${height}，要求 ${viewport.width}×${viewport.height}`);
      }
    } catch (error) {
      failures.push(`${file}：${error.message}`);
    }
  }
  if (failures.length) throw new Error(failures.join('\n'));
  return expected.size;
}
