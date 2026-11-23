import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { collectorPrototypeScreens } from '../src/data/collectorNavigation.ts';
import { browserManifest, checkGallery, galleryFiles, planGallery, viewport } from './screenshot-gallery.mjs';

// 提供 JPEG 文件头和尺寸段，完整图像由重拍脚本实际生成。
function jpeg(width = viewport.width, height = viewport.height) {
  const bytes = Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0, 0, 0, 0, 1, 1, 0x11, 0, 0xff, 0xd9]);
  bytes.writeUInt16BE(height, 7);
  bytes.writeUInt16BE(width, 9);
  return bytes;
}

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'starbeacon-gallery-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const state = { image: 'alerts/data.jpg', state: 'data', title: '有数据', url: '/alerts/list?state=data' };
  const manifest = {
    version: 1,
    viewport,
    groups: [{ id: 'alerts', title: '告警中心' }],
    pages: [{ id: 'alerts', title: '告警列表', group: 'alerts', states: [state] }],
  };
  const save = async () => {
    await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest));
    await writeFile(join(directory, 'manifest.js'), browserManifest(manifest));
  };
  await mkdir(join(directory, 'alerts'));
  await writeFile(join(directory, state.image), jpeg());
  await save();
  return { directory, manifest, state, save };
}

test('独立图库的清单与图片均齐全', async t => {
  const { directory } = await fixture(t);
  assert.equal(await checkGallery(directory), 1);
});

test('浏览器清单与 JSON 清单一致', async t => {
  const { directory } = await fixture(t);
  await writeFile(join(directory, 'manifest.js'), 'window.StarBeaconScreenshotManifest = {};\n');
  await assert.rejects(checkGallery(directory), /浏览器清单.*不一致/);
});

test('报告缺图和未登记的图片', async t => {
  const { directory, state } = await fixture(t);
  await rm(join(directory, state.image));
  await writeFile(join(directory, 'alerts', 'extra.jpg'), jpeg());
  await assert.rejects(checkGallery(directory), /alerts\/extra\.jpg 未登记.*\nalerts\/data\.jpg 缺少截图/);
});

test('拒绝清单外路径与重复登记', async t => {
  const { directory, manifest, state, save } = await fixture(t);
  state.image = '../data.jpg';
  await save();
  await assert.rejects(checkGallery(directory), /截图路径或链接无效/);
  state.image = 'alerts/data.jpg';
  manifest.pages.push({ ...manifest.pages[0], id: 'alerts-copy' });
  await save();
  await assert.rejects(checkGallery(directory), /重复登记：alerts\/data\.jpg/);
});

test('清单和所有图像都必须使用规定视口', async t => {
  const { directory, manifest, state, save } = await fixture(t);
  manifest.viewport = { ...viewport, height: 901 };
  await save();
  await assert.rejects(checkGallery(directory), /视口无效/);
  manifest.viewport = viewport;
  await save();
  for (const [width, height] of [
    [1439, 900],
    [1440, 901],
  ]) {
    await writeFile(join(directory, state.image), jpeg(width, height));
    await assert.rejects(checkGallery(directory), new RegExp(`尺寸为 ${width}×${height}，要求 1440×900`));
  }
});

test('损坏的 JPEG 文件会返回对应路径', async t => {
  const { directory, state } = await fixture(t);
  await writeFile(join(directory, state.image), jpeg().subarray(0, -2));
  await assert.rejects(checkGallery(directory), /alerts\/data\.jpg：JPEG 文件头或结束标记无效/);
  await writeFile(join(directory, state.image), Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0, 2, 0xff, 0xd9]));
  await assert.rejects(checkGallery(directory), /alerts\/data\.jpg：JPEG 尺寸段不完整/);
});

test('每个主控视图保留数据图，九类保留各自的代表状态', async () => {
  const catalog = JSON.parse(await readFile(new URL('../public/page-manifest.json', import.meta.url), 'utf8'));
  const gallery = planGallery(catalog, collectorPrototypeScreens);
  const platform = gallery.pages.filter(page => page.group !== 'collector' && page.group !== 'boundary');
  assert.deepEqual(
    platform.map(page => page.id),
    catalog.pages.map(page => page.id),
  );
  assert.ok(platform.every(page => page.states.some(state => state.state === 'data')));
  const representatives = platform.filter(page => page.states.length > 1);
  assert.equal(representatives.length, 9);
  for (const page of representatives) {
    assert.deepEqual(page.states.map(state => state.state).sort(), [
      'action',
      'data',
      'detail',
      'empty',
      'error',
      'loading',
    ]);
  }
  assert.equal(new Set(representatives.map(page => catalog.pages.find(entry => entry.id === page.id).kind)).size, 9);
  const boundaryCount = catalog.boundary.length + catalog.collector.boundary.length;
  assert.equal(
    galleryFiles(gallery).size,
    catalog.pages.length + 45 + collectorPrototypeScreens.length + boundaryCount,
  );
});

test('清单覆盖采集器规范路由与两端登录和访问边界', async () => {
  const catalog = JSON.parse(await readFile(new URL('../public/page-manifest.json', import.meta.url), 'utf8'));
  const gallery = planGallery(catalog, collectorPrototypeScreens);
  const collector = gallery.pages.filter(page => page.group === 'collector');
  const boundary = gallery.pages.filter(page => page.group === 'boundary');
  assert.deepEqual(
    collector.map(page => page.states[0].url),
    collectorPrototypeScreens.map(view => `${view.path}?state=data`),
  );
  assert.ok(collector.every(page => page.states.length === 1 && page.states[0].state === 'data'));
  assert.deepEqual(
    boundary.map(page => page.states[0].url),
    [...catalog.boundary, ...catalog.collector.boundary].map(page => page.url),
  );
});
