<script setup lang="ts">
import {computed,shallowRef,useId,watch} from 'vue'
import {message,Radio,Pagination as APagination} from 'ant-design-vue'
import {byteNeedle,decodeUTF8,eveBytes,findBytes,hexRows,highlightedHex,type ByteSearch} from '../evidence'
const ARadioGroup=Radio.Group,ARadioButton=Radio.Button
const props=defineProps<{original:string;source?:'eve'|'frame'}>()
const mode=shallowRef('hex'),page=shallowRef(1)
const searchKind=shallowRef<'hex'|'utf8'>('utf8'),query=shallowRef(''),searchError=shallowRef(''),search=shallowRef<ByteSearch>(),matchIndex=shallowRef(0),matchLength=shallowRef(0),searchId=useId()
const evidence=computed(()=>eveBytes(props.original)),bytes=computed(()=>evidence.value.state==='available'?evidence.value.bytes:new Uint8Array()),text=computed(()=>decodeUTF8(bytes.value))
const rendered=computed(()=>mode.value==='hex'?hexRows(bytes.value,(page.value-1)*256,256):text.value.text)
const activeOffset=computed(()=>search.value?.offsets[matchIndex.value]),fragments=computed(()=>highlightedHex(bytes.value,(page.value-1)*256,activeOffset.value===undefined?undefined:{offset:activeOffset.value,length:matchLength.value}))
function resetSearch() {search.value=undefined;searchError.value='';matchIndex.value=0;matchLength.value=0}
watch([query,searchKind],resetSearch)
watch(()=>props.original,()=>{mode.value='hex';page.value=1;query.value='';resetSearch()})
function locate(index:number) {matchIndex.value=index;const offset=activeOffset.value;if(offset!==undefined) {mode.value='hex';page.value=Math.floor(offset/256)+1}}
function submitSearch() {
  resetSearch()
  try {const needle=byteNeedle(query.value,searchKind.value);matchLength.value=needle.length;search.value=findBytes(bytes.value,needle);locate(0)}
  catch(error) {searchError.value=error instanceof Error?error.message:'字节查找失败，请核对输入内容'}
}
async function copy() {try {await navigator.clipboard.writeText(rendered.value);message.success('已复制当前内容')} catch {message.error('复制失败，请选择内容后手动复制')}}
</script>
<template>
  <section aria-label="字节证据" class="byte-viewer">
    <div class="byte-toolbar"><h2>字节证据</h2><a-radio-group v-if="evidence.state==='available'" v-model:value="mode" size="small" aria-label="字节展示方式"><a-radio-button value="hex">HEX</a-radio-button><a-radio-button value="utf8">UTF-8</a-radio-button></a-radio-group><a-button v-if="evidence.state==='available' && (mode==='hex'||text.valid)" size="small" @click="copy">复制当前内容</a-button></div>
    <template v-if="evidence.state==='available'">
      <p class="page-description">{{evidence.kind==='packet'?'数据包字节':'应用载荷字节'}} · {{bytes.length.toLocaleString('zh-CN')}} B。{{source==='frame'?'内容为已核验原包的实际捕获字节，单包不证明完整会话或握手。':'内容为 EVE 导出副本，完整会话及握手需对照 PCAP。'}}</p>
      <form class="byte-search" aria-label="字节查找" @submit.prevent="submitSearch">
        <a-radio-group v-model:value="searchKind" size="small" aria-label="字节查找方式"><a-radio-button value="utf8">文本</a-radio-button><a-radio-button value="hex">HEX</a-radio-button></a-radio-group>
        <label :for="searchId">查找内容</label><a-input :id="searchId" v-model:value="query" :maxlength="4096" :placeholder="searchKind==='hex'?'例如 47 45 54 或 47:45:54':'区分大小写的 UTF-8 文本'" :aria-invalid="Boolean(searchError)" :aria-describedby="searchError?`${searchId}-error`:undefined" allow-clear class="byte-search-input" />
        <a-button html-type="submit" size="small">查找</a-button>
      </form>
      <p v-if="searchError" :id="`${searchId}-error`" class="byte-error" role="alert">{{searchError}}</p>
      <div v-if="search" class="byte-matches" role="status" aria-live="polite">
        <template v-if="search.offsets.length"><span>{{search.limited?'前 ':''}}{{search.offsets.length.toLocaleString('zh-CN')}} 处匹配 · 第 {{matchIndex+1}} 处 · 字节偏移 0x{{activeOffset!.toString(16).padStart(8,'0')}}（{{activeOffset}} B）</span><a-button size="small" :disabled="matchIndex===0" @click="locate(matchIndex-1)">上一处</a-button><a-button size="small" :disabled="matchIndex===search.offsets.length-1" @click="locate(matchIndex+1)">下一处</a-button><a-button size="small" @click="locate(matchIndex)">定位当前</a-button></template>
        <span v-else>未找到匹配内容</span>
        <span v-if="search.limited" class="page-description">匹配过多，仅保留前 1,000 处；请缩小查找范围。</span>
      </div>
      <a-alert v-if="mode==='utf8'&&!text.valid" type="warning" message="字节包含无效 UTF-8 序列，请使用 HEX 查看" show-icon />
      <pre v-else-if="mode==='hex'" class="byte-content technical"><template v-for="(fragment,index) in fragments" :key="index"><mark v-if="fragment.matched" aria-label="当前匹配字节">{{fragment.text}}</mark><template v-else>{{fragment.text}}</template></template></pre>
      <pre v-else class="byte-content technical">{{rendered || '空字节内容'}}</pre>
      <a-pagination v-if="mode==='hex'&&bytes.length>256" v-model:current="page" :total="bytes.length" :page-size="256" :show-size-changer="false" size="small" :show-total="(total:number)=>`${total.toLocaleString('zh-CN')} B · 每页 256 B`" />
    </template>
    <a-empty v-else-if="evidence.state==='missing'" :description="evidence.message" :image="false" />
    <a-alert v-else type="warning" :message="evidence.message" show-icon />
  </section>
</template>
<style scoped>
.byte-viewer {min-width:0;margin-top:var(--section-gap)}
.byte-toolbar {display:flex;align-items:center;gap:var(--related-gap);flex-wrap:wrap;margin-bottom:var(--related-gap)}
.byte-toolbar h2 {margin:0;margin-right:auto}
.byte-content {overflow:auto;white-space:pre;background:var(--table-header);padding:var(--section-gap);border:1px solid var(--line);border-radius:6px;max-height:320px;font-size:12px;line-height:1.7;tab-size:2}
.byte-viewer .page-description {margin:0 0 var(--related-gap)}
.byte-search,.byte-matches {display:flex;align-items:center;gap:var(--related-gap);flex-wrap:wrap;margin-bottom:var(--related-gap)}
.byte-search-input {flex:1 1 200px;min-width:160px}
.byte-error {color:var(--danger);margin:0 0 var(--related-gap)}
.byte-matches {font-size:12px}
.byte-content mark {background:#fff1b8;color:#614700;outline:1px solid #d48806;border-radius:2px}
</style>
