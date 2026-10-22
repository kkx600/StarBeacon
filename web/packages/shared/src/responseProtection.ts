export interface ResponseProtection {
  schema_version:'response.protection.v1'
  command_sha256:string
  check_sha256:string
  check:{schema_version:'watchlist-response-check.v1';checked_at:string;state_sha256:string;matches:readonly unknown[]}
}

const hash=/^[a-f0-9]{64}$/
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)

// 旧任务可以缺少记录；存在的记录必须绑定单 IP 封禁及其原授权时间窗口。
export function validResponseProtection(value:unknown,kind:string,requestedAt:string,expiresAt:string):value is ResponseProtection|undefined {
  if(value===undefined)return true
  if(kind!=='response.block'||!object(value)||Object.keys(value).length!==4||value.schema_version!=='response.protection.v1'||typeof value.command_sha256!=='string'||!hash.test(value.command_sha256)||typeof value.check_sha256!=='string'||!hash.test(value.check_sha256)||!object(value.check))return false
  const check=value.check
  if(Object.keys(check).length!==4||check.schema_version!=='watchlist-response-check.v1'||typeof check.checked_at!=='string'||typeof check.state_sha256!=='string'||!hash.test(check.state_sha256)||!Array.isArray(check.matches)||check.matches.length!==0)return false
  const at=Date.parse(check.checked_at),requested=Date.parse(requestedAt),expiry=Date.parse(expiresAt)
  return Number.isFinite(at)&&Number.isFinite(requested)&&Number.isFinite(expiry)&&Math.abs(at-requested)<=30000&&at<expiry
}
