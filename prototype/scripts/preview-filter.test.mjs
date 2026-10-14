import test from 'node:test'
import assert from 'node:assert/strict'
import { compilePreviewFilter } from '../src/composables/previewFilter.ts'

const record = { source: '198.51.100.24', destination: '10.20.1.15', mac: '02:00:00:20:01:18', protocol: 'HTTP', method: 'GET', path: '\\documents\\files' }
test('地址族、链路观测与 IPv4 大小比较使用合成字段', () => {
  assert.equal(compilePreviewFilter('ip and eth and ip.src >= 198.51.100.1')(record), true)
  assert.equal(compilePreviewFilter('ip.src < 10.0.0.1')(record), false)
  assert.equal(compilePreviewFilter('ipv6')(record), false)
  assert.equal(compilePreviewFilter('ipv6')({ ...record, source: '2001:db8::1' }), true)
  assert.equal(compilePreviewFilter('eth')({ ...record, mac: undefined }), false)
})
test('原始字符串保留反斜杠，不把未闭合文本当作正常值', () => {
  assert.equal(compilePreviewFilter('http.request.uri contains r"\\documents\\files"')(record), true)
  assert.throws(() => compilePreviewFilter('http.request.uri contains r"unfinished'))
})
test('未支持的索引字段与正则语义保持明确拒绝', () => {
  assert.throws(() => compilePreviewFilter('tenant_id == "other"'))
  assert.throws(() => compilePreviewFilter('http.request.uri matches "x.*"'))
})
