// 保留 RFC 3339 的纳秒部分，用于冻结查询范围与下载回执的精确比较。
export function instant(value:string):bigint|null{
 const match=/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value)
 if(!match)return null
 const milliseconds=Date.parse(match[1]+match[3])
 return Number.isFinite(milliseconds)?BigInt(milliseconds)*1000000n+BigInt((match[2]??'').padEnd(9,'0')):null
}
