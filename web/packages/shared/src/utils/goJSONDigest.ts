// 与 Go encoding/json 的字符转义一致；调用者须按公开契约重建字段顺序。
export async function goJSONDigest(value:unknown):Promise<string> {
 if(!crypto.subtle)throw new Error('当前浏览器无法核对数据摘要，请通过 HTTPS 或本机安全入口访问。')
 const encoded=JSON.stringify(value).replace(/[<>&\u2028\u2029]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'))
 const sum=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(encoded))
 return Array.from(new Uint8Array(sum),n=>n.toString(16).padStart(2,'0')).join('')
}
