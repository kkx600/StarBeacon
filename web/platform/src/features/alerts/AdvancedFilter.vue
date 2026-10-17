<script setup lang="ts">
import { computed, nextTick, shallowRef, useId, useTemplateRef, watch } from 'vue'
import SearchFieldCatalog from './SearchFieldCatalog.vue'
import { insertSearchField, suggestFields } from './filterCompletion'
import { useSearchFields } from './useSearchFields'

const model = defineModel<string>({ required: true })
const props = withDefaults(defineProps<{ disabled: boolean; dataset?: 'alerts' | 'context' }>(), { dataset: 'alerts' })
const { fields, error, loading, reload } = useSearchFields(() => props.dataset)
const open = shallowRef(false), focused = shallowRef(false), dismissed = shallowRef(false), explicit = shallowRef(false)
const cursor = shallowRef(0), active = shallowRef(0), insertionError = shallowRef('')
const suggestionGroup = useTemplateRef<HTMLElement>('suggestionGroup')
const inputId = `search-expression-${useId()}`
let textarea: HTMLTextAreaElement | undefined
const suggestions = computed(() => focused.value && !dismissed.value && !props.disabled ? suggestFields(model.value, cursor.value, fields.value, explicit.value) : [])

function track(event: Event) {
  if (event.target instanceof HTMLTextAreaElement) { textarea = event.target; cursor.value = textarea.selectionStart }
}
function input(event: Event) { track(event); focused.value = true; dismissed.value = false; explicit.value = false; active.value = 0; insertionError.value = '' }
function focus(event: Event) { track(event); focused.value = true }
function blur(event: FocusEvent) {
  if (event.relatedTarget instanceof Node && suggestionGroup.value?.contains(event.relatedTarget)) return
  focused.value = false
}
function insert(name: string) {
  if (props.disabled) return
  const field = fields.value.find(value => value.name === name)
  if (!field) return
  const result = insertSearchField(model.value, Math.min(cursor.value, model.value.length), field)
  if (new TextEncoder().encode(result.value).length > 4096) { insertionError.value = '表达式不能超过 4096 字节，请先精简条件'; return }
  insertionError.value = ''
  model.value = result.value; cursor.value = result.cursor; open.value = false; dismissed.value = true; explicit.value = false
  void nextTick(() => { textarea?.focus(); textarea?.setSelectionRange(result.cursor, result.cursor) })
}
function keydown(event: KeyboardEvent) {
  if (props.disabled || event.isComposing) return
  if (event.ctrlKey && (event.code === 'Space' || event.key === ' ')) { event.preventDefault(); track(event); dismissed.value = false; focused.value = true; explicit.value = true; active.value = 0; return }
  if (event.key === 'Escape') { event.preventDefault(); dismissed.value = true; textarea?.focus(); return }
  if (!suggestions.value.length) return
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    const fromInput = event.target instanceof HTMLTextAreaElement
    active.value = fromInput ? event.key === 'ArrowDown' ? 0 : suggestions.value.length - 1 : (active.value + (event.key === 'ArrowDown' ? 1 : -1) + suggestions.value.length) % suggestions.value.length
    const buttons = suggestionGroup.value?.querySelectorAll<HTMLButtonElement>('button')
    buttons?.[active.value]?.focus()
  } else if (event.key === 'Enter' && event.target instanceof HTMLTextAreaElement) {
    event.preventDefault(); insert(suggestions.value[active.value]!.name)
  }
}
watch(() => props.disabled, disabled => { if (disabled) { open.value = false; focused.value = false } })
watch(suggestions, items => { if (active.value >= items.length) active.value = 0 })
</script>
<template>
  <div class="advanced-filter">
    <div class="advanced-label"><label :for="inputId">高级过滤表达式</label><a-button size="small" :disabled="disabled" @click="open = true">字段目录</a-button></div>
    <a-textarea :id="inputId" v-model:value="model" :disabled="disabled" :maxlength="4096" :auto-size="{ minRows: 2, maxRows: 5 }" class="technical" placeholder='tcp.port in {80 443} and http.request.uri contains "/api"' :aria-describedby="`${inputId}-help`" @focus="focus" @blur="blur" @input="input" @select="track" @click="track" @keyup="track" @keydown="keydown" />
    <div v-if="suggestions.length" ref="suggestionGroup" role="group" aria-label="检索字段建议" class="filter-suggestions" @keydown="keydown" @focusout="blur">
      <button v-for="(field, index) in suggestions" :key="field.name" type="button" :class="{ selected: active === index }" @focus="active = index" @mousedown.prevent @click="insert(field.name)"><span class="technical">{{ field.name }}</span><span>{{ field.label }}</span></button>
    </div>
    <p :id="`${inputId}-help`" class="page-description">作用于{{ dataset === 'context' ? '协议事件' : '告警' }}索引。支持 and／or／not、括号、比较、contains、in、端口范围及原始字符串。输入字段前缀可补全，Ctrl＋空格查看建议，方向键选择，Esc 关闭。尚未提供原生逐包检索。</p>
    <a-alert v-if="insertionError" :message="insertionError" type="warning" show-icon />
    <SearchFieldCatalog :open="open" :fields="fields" :error="error" :loading="loading" :disabled="disabled" :dataset="dataset" @close="open = false" @retry="reload" @insert="insert" />
  </div>
</template>
<style scoped>
.advanced-filter {grid-column:1/-1;min-width:0;margin-bottom:var(--panel-inset)}
.advanced-label {display:flex;justify-content:space-between;align-items:center;gap:var(--related-gap);margin-bottom:var(--related-gap)}
.advanced-filter .page-description {margin:var(--label-gap) 0 0;line-height:1.6}
.filter-suggestions {display:grid;gap:2px;margin-top:4px;padding:4px;border:1px solid var(--control-border);border-radius:8px;background:var(--surface);max-height:248px;overflow:auto}
.filter-suggestions button {display:flex;flex-wrap:wrap;justify-content:space-between;gap:4px 12px;padding:6px 10px;border:0;border-radius:4px;background:transparent;color:var(--text);text-align:left;cursor:pointer;overflow-wrap:anywhere}
.filter-suggestions button.selected,.filter-suggestions button:hover {background:var(--selection-surface);color:var(--selection-text)}
.filter-suggestions button:focus-visible {outline:2px solid var(--primary);outline-offset:-2px}
</style>
