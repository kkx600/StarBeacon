type Quantity = number | string | bigint | null | undefined
const decimal = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']
const binary = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
const rates = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s', 'Pbit/s', 'Ebit/s']

// 整数字符串保留大计数精度；显示值有界，原始计数仍用于存储、计算和导出。
function scaled(value: Quantity, units: string[], base: number): string {
  if (value === null || value === undefined || value === '') return '未获取'
  if (typeof value === 'bigint' || (typeof value === 'string' && /^\d+$/.test(value))) {
    const amount = BigInt(value)
    if (amount < 0n) return '未获取'
    let index = 0, divisor = 1n
    while (amount >= divisor * BigInt(base) && index < units.length - 1) { divisor *= BigInt(base); index++ }
    let hundredths = (amount * 100n + divisor / 2n) / divisor
    if (hundredths >= BigInt(base * 100) && index < units.length - 1) { divisor *= BigInt(base); index++; hundredths = (amount * 100n + divisor / 2n) / divisor }
    if (hundredths > 100000000n) return `>1000000 ${units[index]}`
    const text = `${hundredths / 100n}.${String(hundredths % 100n).padStart(2, '0')}`.replace(/\.?0+$/, '')
    return `${text} ${units[index]}`
  }
  let amount = Number(value)
  if (!Number.isFinite(amount) || amount < 0) return '未获取'
  let index = 0
  while (amount >= base && index < units.length - 1) { amount /= base; index++ }
  if (Number(amount.toFixed(2)) >= base && index < units.length - 1) { amount /= base; index++ }
  if (amount > 1000000) return `>1000000 ${units[index]}`
  return `${new Intl.NumberFormat('zh-CN', {maximumFractionDigits: 2, useGrouping: false}).format(amount)} ${units[index]}`
}

export const formatBytes = (value: Quantity, binaryUnits = false) => scaled(value, binaryUnits ? binary : decimal, binaryUnits ? 1024 : 1000)
export const formatBitRate = (value: Quantity) => scaled(value, rates, 1000)

// 原型兼容已有带单位的合成记录；未知单位保持原文，不能把速率解释为容量。
export function formatQuantity(value: unknown): string {
  if (value === null || value === undefined) return '未提供'
  if (typeof value === 'number' || typeof value === 'bigint') return formatBytes(value)
  const text = String(value)
  if (/^\s*[+-]?\d+(?:\.\d+)?\s*$/.test(text)) return formatBytes(text.trim())
  const match = /^\s*(\d+(?:\.\d+)?)\s*(B|[KMGTPE](?:i)?B|(?:[KMGTPE])?(?:bit|b)\/s)\s*$/i.exec(text)
  if (!match) return text
  const unit = match[2]!, prefix = unit[0]!.toUpperCase(), power = 'KMGTPE'.indexOf(prefix) + 1
  const binaryUnit = /iB$/i.test(unit)
  const amount = Number(match[1]) * (binaryUnit ? 1024 : 1000) ** power
  return /(?:bit|b)\/s$/i.test(unit) ? formatBitRate(amount) : formatBytes(amount, binaryUnit)
}

// 排序使用未取整的数量，整数计数和不同单位转换均保留精度。
export function compareQuantity(left: unknown, right: unknown): number {
  const parse = (value: unknown) => {
    const match = /^\s*(\d+)(?:\.(\d+))?\s*(B|[KMGTPE](?:i)?B|(?:[KMGTPE])?(?:bit|b)\/s)?\s*$/i.exec(String(value ?? ''))
    if (!match) return null
    const fraction = match[2] ?? '', unit = match[3] ?? ''
    const power = unit ? 'KMGTPE'.indexOf(unit[0]!.toUpperCase()) + 1 : 0
    return {amount: BigInt(match[1]! + fraction) * BigInt(/iB$/i.test(unit) ? 1024 : 1000) ** BigInt(power), divisor: 10n ** BigInt(fraction.length), kind: unit ? (/\/s$/i.test(unit) ? 'rate' : 'bytes') : ''}
  }
  const a = parse(left), b = parse(right)
  if (a && b && (!a.kind || !b.kind || a.kind === b.kind)) {
    const difference = a.amount * b.divisor - b.amount * a.divisor
    return difference < 0n ? -1 : difference > 0n ? 1 : 0
  }
  return String(left ?? '').localeCompare(String(right ?? ''), 'zh-CN', {numeric: true})
}
