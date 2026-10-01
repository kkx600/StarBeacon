import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {compareQuantity,formatBytes,formatBitRate,formatQuantity} from '../packages/shared/src/utils/format.ts'
import {safeReturnPath} from '../packages/shared/src/utils/history.ts'
import {inspectRules} from '../packages/shared/src/utils/ruleSyntax.ts'
import {palette as actual} from '../packages/shared/src/theme.ts'
import {palette as prototype} from '../../prototype/src/theme.ts'
const rule='alert http any any -> $HOME_NET any (msg:"样例"; http.uri; content:"/admin"; sid:1000001; rev:1;)'
test('容量与速率自动换算，缺测与零区分，64 位计数保留精度',()=>{
 assert.equal(formatBytes(0),'0 B');assert.equal(formatBytes(null),'未获取')
 assert.equal(formatBytes(-1),'未获取');assert.equal(formatBytes(Infinity),'未获取')
 assert.equal(formatBytes(1000),'1 KB');assert.equal(formatBytes(10**6),'1 MB');assert.equal(formatBytes(10**9),'1 GB');assert.equal(formatBytes(10**12),'1 TB')
 assert.equal(formatBytes(1024,true),'1 KiB');assert.equal(formatBytes('18446744073709551615'),'18.45 EB')
 assert.equal(formatBytes('999999999'),'1 GB');assert.equal(formatBitRate(10**9),'1 Gbit/s')
 assert.equal(formatQuantity('12000 Mbit/s'),'12 Gbit/s');assert.equal(formatQuantity('2048 MiB'),'2 GiB');assert.equal(formatQuantity('不可观测'),'不可观测')
 assert.equal(formatBytes(10n**40n),'>1000000 EB')
 assert.equal(formatBytes(10**40),'>1000000 EB');assert.equal(formatQuantity('18446744073709551615'),'18.45 EB')
 assert.equal(compareQuantity('900 MB','1 GB'),-1);assert.equal(compareQuantity('1024 KiB','1 MiB'),0)
 assert.equal(compareQuantity('18446744073709551614','18446744073709551615'),-1)
 assert.equal(compareQuantity('1000 Mbit/s','1 Gbit/s'),0)
})
test('登录回跳只接受同源应用路径，并保留查询和锚点',()=>{
 assert.equal(safeReturnPath('/rules?view=tasks#receipt','/sensors'),'/rules?view=tasks#receipt')
 for(const value of ['https://evil.test','//evil.test','/%2fevil.test','/\\evil.test','/%5cevil.test','/login','/login/again','/bad%','/\npath',[]])assert.equal(safeReturnPath(value,'/sensors'),'/sensors')
})
test('基础规则检查定位重复 SID、缺分号、引号、头部、动作和空包',()=>{
 assert.deepEqual(inspectRules(rule),[])
 assert.deepEqual(inspectRules('alert tcp [192.0.2.1, 198.51.100.0/24] any <> $HOME_NET [80, 443] (msg:"A\\\"B"; content:"|3B|"; sid:2;)'),[])
 assert.equal(inspectRules(rule+'\n'+rule)[0].line,2)
 for(const value of ['', '# 仅注释', rule.replace('alert ','drop '),rule.replace('rev:1;','rev:1'),rule.replace('sid:1000001;','sid:0;'),rule.replace('"/admin"','"/admin'),rule.replace(' -> ',' <- '),rule+'\0'])assert.ok(inspectRules(value).length)
 assert.deepEqual(inspectRules(rule.replace('http.uri;','unknown_keyword;')),[],'引擎关键词不能由浏览器假装验证')
 assert.ok(inspectRules('x'.repeat(900*1024+1))[0].message.includes('900 KiB'))
})
test('两端与原型采用 History，API 与资源不会被 SPA 回退覆盖',async()=>{
 for(const path of ['../platform/src/router.ts','../collector/src/router.ts','../../prototype/src/router.ts']){
  const source=await readFile(new URL(path,import.meta.url),'utf8');assert.ok(source.includes('createWebHistory'));assert.ok(!source.includes('createWebHashHistory'))
 }
 for(const name of ['platform','collector']){const config=await readFile(new URL(`../../deploy/nginx/${name}.conf`,import.meta.url),'utf8');assert.ok(config.includes('location ^~ /api/'));assert.ok(config.includes('location ^~ /assets/'));assert.ok(config.includes('try_files $uri =404'));assert.ok(config.includes('try_files $uri $uri/ /index.html'))}
})

test('工程与原型语义色一致，语法文本在白灰底上可读',()=>{
 assert.deepEqual(actual,prototype)
 const luminance=hex=>{const c=hex.slice(1).match(/../g).map(x=>parseInt(x,16)/255).map(x=>x<=0.04045?x/12.92:((x+0.055)/1.055)**2.4);return c[0]*0.2126+c[1]*0.7152+c[2]*0.0722}
 for(const key of ['link','success','muted','text','syntaxVariable','syntaxOption','syntaxNumber'])for(const base of ['surface','tableHeader']){const values=[luminance(actual[key]),luminance(actual[base])].sort((a,b)=>b-a);assert.ok((values[0]+0.05)/(values[1]+0.05)>=4.5,key)}
})
