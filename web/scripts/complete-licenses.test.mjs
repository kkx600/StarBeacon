/** 在隔离制品目录验证许可来源篡改、版本错配与文件边界。 */
import {test} from 'node:test'
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdtempSync, writeFileSync, readFileSync, rmSync, symlinkSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {completeLicenses} from './complete-licenses.mjs'

const hash = text => createHash('sha256').update(text).digest('hex')
function fixture(t, records = [{name: 'example', version: '1.2.3', identifier: 'MIT', text: ''}]) {
  const root = mkdtempSync(join(tmpdir(), 'starbeacon-license-'))
  t.after(() => rmSync(root, {recursive: true, force: true}))
  const path = join(root, 'inventory.json'), source = join(root, 'sources.json'), license = join(root, 'example.LICENSE.txt')
  const text = 'Copyright isolated test fixture\nPermission fixture only.\n'
  const record = {name: 'example', version: '1.2.3', identifier: 'MIT', file: 'example.LICENSE.txt', sha256: hash(text), source: 'https://raw.githubusercontent.com/example/repository/test/LICENSE'}
  const sources = {schema_version: 1, packages: [record]}
  writeFileSync(path, JSON.stringify(records)); writeFileSync(source, JSON.stringify(sources)); writeFileSync(license, text)
  return {root, path, source, license, text, sources, records}
}
test('缺失文本仅由已核对的同包同版本原文补齐，已有文本不被替换', t => {
  const f = fixture(t, [{name: 'example', version: '1.2.3', identifier: 'MIT', text: ''}, {name: 'bundled', version: '2.0.0', identifier: 'Apache-2.0', text: '实际构建许可文本'}])
  assert.equal(completeLicenses(f.path, f.root), 2)
  const [supplemented, retained] = JSON.parse(readFileSync(f.path, 'utf8'))
  assert.equal(supplemented.text, f.text); assert.equal(supplemented.sha256, hash(f.text)); assert.equal(supplemented.source, f.sources.packages[0].source)
  assert.equal(retained.text, '实际构建许可文本'); assert.equal(retained.sha256, hash(retained.text)); assert.equal(retained.source, undefined)
  assert.equal(completeLicenses(f.path, f.root), 2)
})
test('相同 SPDX 标识不能用于未知包、版本或不同许可', t => {
  for (const record of [{name: 'other', version: '1.2.3', identifier: 'MIT', text: ''}, {name: 'example', version: '1.2.4', identifier: 'MIT', text: ''}, {name: 'example', version: '1.2.3', identifier: 'ISC', text: ''}]) {
    const f = fixture(t, [record]), original = readFileSync(f.path)
    assert.throws(() => completeLicenses(f.path, f.root), /已核对许可原文/)
    assert.deepEqual(readFileSync(f.path), original)
  }
})
test('许可原文篡改或来源重复不能生成交付清单', t => {
  const f = fixture(t), original = readFileSync(f.path)
  writeFileSync(f.license, '被篡改的文本')
  assert.throws(() => completeLicenses(f.path, f.root), /摘要/); assert.deepEqual(readFileSync(f.path), original)
  writeFileSync(f.license, f.text)
  f.sources.packages.push({...f.sources.packages[0]}); writeFileSync(f.source, JSON.stringify(f.sources))
  assert.throws(() => completeLicenses(f.path, f.root), /来源无效/)
})
test('空目录、缺少身份、重复依赖、符号链接或越界文件均拒绝', t => {
  for (const records of [[], null, [{name: '', version: '1', identifier: 'MIT'}], [{name: 'example', version: '1.2.3', identifier: 'MIT', text: ''}, {name: 'example', version: '1.2.3', identifier: 'MIT', text: ''}]]) {
    const f = fixture(t, records)
    assert.throws(() => completeLicenses(f.path, f.root))
  }
  const f = fixture(t)
  f.sources.packages[0].file = '../outside.LICENSE.txt'; writeFileSync(f.source, JSON.stringify(f.sources))
  assert.throws(() => completeLicenses(f.path, f.root), /来源无效/)
  const g = fixture(t), link = join(g.root, 'link.json'); symlinkSync(g.path, link)
  assert.throws(() => completeLicenses(link, g.root), /普通文件/)
})
