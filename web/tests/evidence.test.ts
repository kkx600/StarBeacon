import { describe, expect, it } from 'vitest'
import { byteNeedle,decodeUTF8,eveBytes,findBytes,hexRows,highlightedHex } from '../packages/shared/src/evidence'

describe('字节证据边界', () => {
  it('区分数据包、载荷及无证据，不把 EVE JSON 当成数据包', () => {
    const bytes=new Uint8Array([0,1,65,255])
    const encoded=btoa(String.fromCharCode(...bytes))
    expect(eveBytes(JSON.stringify({packet:encoded}))).toEqual({state:'available',kind:'packet',bytes})
    expect(eveBytes(JSON.stringify({payload:encoded}))).toEqual({state:'available',kind:'payload',bytes})
    for(const raw of ['', '{}', JSON.stringify({packet:''}), JSON.stringify({payload:null})])expect(eveBytes(raw).state).toBe('missing')
    for(const raw of ['invalid','null','[]','true',JSON.stringify({packet:4}),JSON.stringify({packet:'!!!!'}),JSON.stringify({packet:'AAAAA'}),JSON.stringify({packet:'A'.repeat(1398105)}),JSON.stringify({packet:'A'.repeat(1398104)})])expect(eveBytes(raw).state).toBe('invalid')
    expect(eveBytes(JSON.stringify({packet:'invalid?',payload:encoded})).state).toBe('invalid')
  })
  it('按真实字节偏移分页并限制单次渲染量', () => {
    const bytes=Uint8Array.from({length:600},(_,index)=>index%256)
    const first=hexRows(bytes,0,16),second=hexRows(bytes,256,16)
    expect(first).toBe('00000000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|')
    expect(second.startsWith('00000100')).toBe(true)
    expect(hexRows(new Uint8Array([65,32,126,255]))).toContain('|A ~.|')
    expect(hexRows(bytes,599,256)).toContain('00000257')
    expect(hexRows(bytes,600)).toBe('')
    expect(hexRows(bytes,0,-1)).toBe('')
    expect(hexRows(new Uint8Array(5000),0,9000).split('\n')).toHaveLength(256)
    expect(hexRows(bytes,-10,1).startsWith('00000000')).toBe(true)
  })
  it('严格尝试 UTF-8，不用替换字符掩盖无效字节', () => {
    expect(decodeUTF8(new TextEncoder().encode('星烽\n告警'))).toEqual({valid:true,text:'星烽\n告警'})
    expect(decodeUTF8(new Uint8Array([0xff]))).toEqual({valid:false,text:''})
    expect(decodeUTF8(new Uint8Array())).toEqual({valid:true,text:''})
  })
  it('HEX 支持完整字节和常用分隔符，文本按原始 UTF-8 字节精确查找',()=>{
    for(const value of ['00ff41','00 FF 41',' 00:ff:41 ','00 : ff : 41','00\nff\t41'])expect(byteNeedle(value,'hex')).toEqual(new Uint8Array([0,255,65]))
    expect(byteNeedle(' 星烽\n','utf8')).toEqual(new TextEncoder().encode(' 星烽\n'))
    for(const value of ['',' ','0','0 1','0x41','gg','00::41','41:',':41','41-42','a'.repeat(4097),'aa'.repeat(513)])expect(()=>byteNeedle(value,'hex')).toThrow()
    for(const value of ['','\ud800','\udfff','a'.repeat(513),'星'.repeat(171)])expect(()=>byteNeedle(value,'utf8')).toThrow()
    expect(byteNeedle('a'.repeat(512),'utf8')).toHaveLength(512)
    expect(byteNeedle('😀','utf8')).toHaveLength(4)
  })
  it('保留重叠、跨行、跨页和多字节文本匹配，偏移始终按字节',()=>{
    expect(findBytes(new TextEncoder().encode('aaaaa'),byteNeedle('aaa','utf8'))).toEqual({offsets:[0,1,2],limited:false})
    const raw=new Uint8Array(600);raw.set([0xff,0x41,0x42],255);raw.set([0xff,0x41,0x42],511)
    expect(findBytes(raw,byteNeedle('ff 41 42','hex'))).toEqual({offsets:[255,511],limited:false})
    expect(findBytes(new TextEncoder().encode('星烽星烽'),byteNeedle('烽','utf8')).offsets).toEqual([3,9])
    expect(findBytes(new TextEncoder().encode('GET'),byteNeedle('get','utf8')).offsets).toEqual([])
    expect(findBytes(new Uint8Array(),new Uint8Array([1])).offsets).toEqual([])
  })
  it('重复载荷限制匹配数量，不把截断结果当作精确总数',()=>{
    expect(findBytes(new Uint8Array(1000),new Uint8Array([0]))).toEqual({offsets:Array.from({length:1000},(_,index)=>index),limited:false})
    const found=findBytes(new Uint8Array(1024*1024),new Uint8Array([0]));expect(found.offsets).toHaveLength(1000);expect(found.limited).toBe(true)
    for(const [bytes,needle] of [[new Uint8Array(),new Uint8Array()],[new Uint8Array(1024*1024+1),new Uint8Array([1])],[new Uint8Array(),new Uint8Array(513)]] as const)expect(()=>findBytes(bytes,needle)).toThrow()
    // 反复部分匹配仍能回退到正确边界，而非跳过后续合法命中。
    expect(findBytes(new TextEncoder().encode('ababababacababac'),byteNeedle('ababac','utf8')).offsets).toEqual([4,10])
  })
  it('随机短样本与逐字节参考查找一致',()=>{
    let seed=17
    const next=()=>{seed=(seed*1664525+1013904223)>>>0;return seed%4}
    for(let sample=0;sample<100;sample++) {
      const bytes=Uint8Array.from({length:64},next),needle=Uint8Array.from({length:sample%8+1},next),expected:number[]=[]
      for(let offset=0;offset+needle.length<=bytes.length;offset++)if(needle.every((byte,index)=>byte===bytes[offset+index]))expected.push(offset)
      expect(findBytes(bytes,needle)).toEqual({offsets:expected,limited:false})
    }
  })
  it('高亮保留原始 HEX 文本，只标记本页实际存在的字节',()=>{
    const bytes=Uint8Array.from({length:600},(_,index)=>index%256)
    const first=highlightedHex(bytes,256,{offset:511,length:3}),next=highlightedHex(bytes,512,{offset:511,length:3})
    expect(first.map(part=>part.text).join('')).toBe(hexRows(bytes,256));expect(first.filter(part=>part.matched).map(part=>part.text)).toEqual(['ff'])
    expect(next.filter(part=>part.matched).map(part=>part.text)).toEqual(['00 01'])
    for(const range of [undefined,{offset:-1,length:1},{offset:0,length:0},{offset:0.5,length:2},{offset:900,length:1}])expect(highlightedHex(bytes,0,range).some(part=>part.matched)).toBe(false)
    expect(highlightedHex(bytes,-10,{offset:0,length:1}).filter(part=>part.matched).map(part=>part.text)).toEqual(['00'])
    expect(highlightedHex(bytes,NaN).map(part=>part.text).join('')).toBe(hexRows(bytes,0))
  })
})
