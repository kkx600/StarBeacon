import test from 'node:test'
import assert from 'node:assert/strict'
import {packetPreviewLocation,packetPreviewModes,openPacketPreview,closePacketPreview,selectPacketPreview,selectPacketLayer} from '../src/composables/packetPreview.ts'

const layers=[3,3,3,4,3,3,3,3,3]
test('原包查看默认关闭，只在明确标识下展示固定样本',()=>{
 assert.equal(packetPreviewLocation({},layers).open,false)
 assert.deepEqual(packetPreviewLocation({inspect:'packet'},layers),{open:true,number:1,layer:1,mode:'data',error:''})
 assert.equal(packetPreviewLocation({inspect:'packet',packet:'4',layer:'4'},layers).layer,4)
 assert.equal(packetPreviewLocation({inspect:'packet',packet:'9',layer:'none'},layers).layer,null)
})
test('拒绝非规范包号、数组参数、无效模式及当前包不存在的层',()=>{
 for(const packet of ['0','01','+1','1e0','1.0',' 1','10','9007199254740992',null,['1']])assert.ok(packetPreviewLocation({inspect:'packet',packet},layers).error)
 for(const layer of ['0','01','4',null,['1']])assert.ok(packetPreviewLocation({inspect:'packet',layer},layers).error)
 for(const value of [null,['packet'],'other'])assert.ok(packetPreviewLocation({inspect:value},layers).error)
 for(const inspection of [null,['data'],'complete'])assert.ok(packetPreviewLocation({inspect:'packet',inspection},layers).error)
 assert.ok(packetPreviewLocation({inspect:'packet',inspect_archive:'../private'},layers).error)
})
test('全部展示状态独立可复现，不将失败转换为有数据',()=>{
 for(const mode of packetPreviewModes)assert.equal(packetPreviewLocation({inspect:'packet',inspection:mode},layers).mode,mode)
 assert.equal(packetPreviewLocation({inspect:'packet',packet:'invalid',inspection:'data'},layers).mode,'error')
})
test('打开和关闭只修改专项参数，保留筛选、状态和重复查询条件',()=>{
 const original={state:'data',filter:'ip.src == 192.0.2.1',tag:['one','two'],inspect:'packet',packet:'8',layer:'2',inspection:'expired',inspect_archive:'OLD'}
 const opened=openPacketPreview(original,'PACKET-0001')
 assert.equal(opened.inspect_archive,'PACKET-0001');assert.equal(opened.packet,'1');assert.equal(opened.layer,'1');assert.equal(opened.inspection,'data')
 assert.deepEqual(closePacketPreview(opened),{state:'data',filter:original.filter,tag:['one','two']})
 assert.equal(original.packet,'8')
})
test('切换包复位当前协议层，关闭全部层可通过none保留',()=>{
 assert.deepEqual(selectPacketPreview({inspect:'packet',packet:'4',layer:'4',inspection:'error',filter:'tcp'},5),{inspect:'packet',packet:'5',layer:'1',inspection:'error',filter:'tcp'})
 assert.equal(selectPacketLayer({inspect:'packet'},[]).layer,'none')
 assert.equal(selectPacketLayer({inspect:'packet'},[3,1]).layer,'3')
 for(const value of [0,-1,1.5,NaN,1048577])assert.throws(()=>selectPacketPreview({},value),RangeError)
 assert.throws(()=>selectPacketLayer({},[17]),RangeError)
})
