import type {BusinessRecord} from '../models'

type Predicate=(record:BusinessRecord)=>boolean
const fields:Record<string,string>={'ip.src':'source','ip.dst':'destination','eth.src':'mac','eth.dst':'destinationMac','http.request.method':'method','http.request.uri':'path','tcp.flags.syn':'syn','tcp.stream':'session','dns.qry.name':'domain','tls.handshake.extensions_server_name':'sni'}
function fieldValue(record:BusinessRecord,field:string):unknown{
  if(['http','tcp','udp','tls','dns'].includes(field))return String(record.protocol).toLowerCase()===field
  if(field==='eth.dst')return'02:00:00:20:01:0f'
  if(field==='tcp.flags.syn')return 0
  if(field.startsWith('http.')&&record.protocol!=='HTTP')return undefined
  if(field.startsWith('tls.')&&record.protocol!=='TLS')return undefined
  if(field.startsWith('dns.')&&record.protocol!=='DNS')return undefined
  return record[fields[field]??'']
}
function ipNumber(ip:string):number|undefined{const parts=ip.split('.');if(parts.length!==4||parts.some(p=>!/^\d+$/.test(p)||Number(p)>255))return undefined;return parts.reduce((sum,p)=>(sum*256+Number(p))>>>0,0)}
function equal(left:unknown,right:string):boolean{
  if(/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(right)){const [network,prefixText]=right.split('/');const ip=ipNumber(String(left));const net=ipNumber(network!);const prefix=Number(prefixText);if(ip===undefined||net===undefined||prefix<0||prefix>32)return false;const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0;return (ip&mask)===(net&mask)}
  return String(left)===right
}
// 只对合成字段执行有界示例语法；无法支持的语义明确报错，不模拟成功。
export function compilePreviewFilter(expression:string):Predicate{
  if(!expression.trim())return()=>true
  if(expression.length>1200)throw new Error('示例表达式超过长度限制。')
  const tokens=expression.match(/"(?:[^"\\]|\\.)*"|'[^']*'|==|!=|>=|<=|&&|\|\||[(){}!<>]|[^\s(){}!<>=]+/g)??[]
  let index=0
  const peek=()=>tokens[index]
  const take=()=>{const token=tokens[index++];if(token===undefined)throw new Error('表达式不完整。');return token}
  function literal(token:string){if(token.startsWith('"')){try{return String(JSON.parse(token))}catch{throw new Error('字符串转义不完整。')}}return token.startsWith("'")?token.slice(1,-1):token}
  function atom():Predicate{
    if(peek()==='('){take();const predicate=or();if(take()!==')')throw new Error('括号未配对。');return predicate}
    const field=take();if(!fields[field]&&!['http','tcp','udp','tls','dns'].includes(field))throw new Error(`字段 ${field} 不在合成检索示例范围内。`)
    const operator=peek()
    if(!['==','!=','>','>=','<','<=','contains','in'].includes(operator??''))return r=>{const value=fieldValue(r,field);return value!==undefined&&value!==false}
    take()
    if(operator==='in'){if(take()!=='{')throw new Error('集合需要使用 { }。');const values:string[]=[];while(peek()&&peek()!=='}'){values.push(literal(take()));if(values.length>32)throw new Error('示例集合最多 32 项。')}if(take()!=='}')throw new Error('集合未闭合。');return r=>{const left=fieldValue(r,field);return left!==undefined&&values.some(value=>equal(left,value))}}
    const right=literal(take())
    return r=>{const left=fieldValue(r,field);if(left===undefined)return false;if(operator==='==')return equal(left,right);if(operator==='!=')return !equal(left,right);if(operator==='contains')return String(left).includes(right);const a=Number(left),b=Number(right);if(!Number.isFinite(a)||!Number.isFinite(b))return false;return operator==='>'?a>b:operator==='>='?a>=b:operator==='<'?a<b:a<=b}
  }
  function not():Predicate{if(peek()==='not'||peek()==='!'){take();const inner=not();return r=>!inner(r)}return atom()}
  function and():Predicate{let left=not();while(peek()==='and'||peek()==='&&'){take();const before=left;const right=not();left=r=>before(r)&&right(r)}return left}
  function or():Predicate{let left=and();while(peek()==='or'||peek()==='||'){take();const before=left;const right=and();left=r=>before(r)||right(r)}return left}
  const predicate=or();if(index!==tokens.length)throw new Error(`语义 ${peek()} 不在合成示例执行范围内；请查看生产能力清单。`)
  return predicate
}
