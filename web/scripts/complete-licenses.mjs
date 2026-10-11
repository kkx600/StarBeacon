/** 校对实际前端制品的许可原文；已核对的补充文本只适用于精确的包版本。 */
import {createHash, randomUUID} from 'node:crypto'
import {readFileSync, writeFileSync, renameSync, lstatSync} from 'node:fs'
import {dirname, resolve, basename} from 'node:path'
import {fileURLToPath, pathToFileURL} from 'node:url'

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const checksum = value => createHash('sha256').update(value).digest('hex')
function readOrdinary(path, limit) {
  const stat = lstatSync(path)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > limit) throw new Error('许可输入必须为体积有界的普通文件。')
  return readFileSync(path, 'utf8')
}
export function completeLicenses(path, sourcesRoot = resolve(webRoot, 'licenses')) {
  const records = JSON.parse(readOrdinary(path, 4 * 1024 * 1024))
  const sources = JSON.parse(readOrdinary(resolve(sourcesRoot, 'sources.json'), 256 * 1024))
  if (!Array.isArray(records) || !records.length || records.length > 1000 || sources.schema_version !== 1 || !Array.isArray(sources.packages)) throw new Error('许可目录格式无效。')
  const additions = new Map()
  for (const source of sources.packages) {
    const key = `${source.name}@${source.version}`
    if (additions.has(key) || typeof source.file !== 'string' || basename(source.file) !== source.file || !/^[a-zA-Z0-9_.-]+\.LICENSE\.txt$/.test(source.file)
      || typeof source.source !== 'string' || !source.source.startsWith('https://raw.githubusercontent.com/') || !/^[a-f0-9]{64}$/.test(source.sha256)) throw new Error('补充许可来源无效。')
    const text = readOrdinary(resolve(sourcesRoot, source.file), 1024 * 1024)
    if (!text.trim() || checksum(text) !== source.sha256) throw new Error('补充许可原文与来源摘要不一致。')
    additions.set(key, {...source, text})
  }
  const seen = new Set()
  for (const record of records) {
    if (!record || typeof record.name !== 'string' || !record.name.trim() || typeof record.version !== 'string' || !record.version.trim()
      || typeof record.identifier !== 'string' || !record.identifier.trim()) throw new Error('前端制品缺少依赖身份或许可标识。')
    const key = `${record.name}@${record.version}`
    if (seen.has(key)) throw new Error('前端许可目录包含重复版本。')
    seen.add(key)
    if (typeof record.text !== 'string' || !record.text.trim()) {
      const source = additions.get(key)
      if (!source || source.identifier !== record.identifier) throw new Error(`缺少 ${key} 的已核对许可原文。`)
      record.text = source.text
      record.source = source.source
    }
    record.sha256 = checksum(record.text)
  }
  // 完整校对后再替换文件，避免失败时留下部分完成的交付目录。
  const temporary = path + '.' + randomUUID() + '.tmp'
  writeFileSync(temporary, JSON.stringify(records, null, 2) + '\n', {flag: 'wx'})
  renameSync(temporary, path)
  return records.length
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  if (!['platform', 'collector'].includes(process.argv[2])) throw new Error('必须选择主控平台或采集器制品。')
  const count = completeLicenses(resolve(webRoot, process.argv[2], 'dist/third-party-licenses.json'))
  console.log(`前端制品许可原文校对通过：${count} 个依赖版本。`)
}
