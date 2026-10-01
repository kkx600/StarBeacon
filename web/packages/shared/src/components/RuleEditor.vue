<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue'
import { Compartment, EditorState } from '@codemirror/state'
import { EditorView, highlightActiveLine, keymap, lineNumbers } from '@codemirror/view'
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands'
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from '@codemirror/language'
import { lintGutter, setDiagnostics } from '@codemirror/lint'
import { tags } from '@lezer/highlight'
import { inspectRules } from '../utils/ruleSyntax'
const props = withDefaults(defineProps<{modelValue: string; disabled?: boolean; readonly?: boolean; label?: string}>(), {label: 'Suricata 规则文本'})
const emit = defineEmits<{'update:modelValue': [value: string]}>()
const element = shallowRef<HTMLDivElement>(), diagnostics = computed(() => inspectRules(props.modelValue))
const access = new Compartment()
let view: EditorView | undefined, external = false
const language = StreamLanguage.define({
  token(stream) {
    if (stream.eatSpace()) return null
    if (stream.match(/^#.*/)) return 'comment'
    if (stream.match(/^"(?:[^"\\]|\\.)*"/)) return 'string'
    if (stream.match(/^\$[A-Za-z_][\w]*/)) return 'variableName'
    if (stream.match(/^(?:alert|drop|reject|pass|tcp|udp|http|tls|dns|ip|icmp|ssh|smb|quic)\b/)) return 'keyword'
    if (stream.match(/^(?:->|<>|[:;(),\[\]!])/)) return 'operator'
    if (stream.match(/^\d+(?:\.\d+)*(?:\/\d+)?/)) return 'number'
    if (stream.match(/^[A-Za-z_][\w.-]*(?=\s*[:;])/)) return 'propertyName'
    stream.next(); return null
  },
})
const colors = HighlightStyle.define([
  {tag: tags.keyword, color: 'var(--link)', fontWeight: '600'}, {tag: tags.string, color: 'var(--success)'},
  {tag: tags.variableName, color: 'var(--syntax-variable)'}, {tag: tags.propertyName, color: 'var(--syntax-option)'},
  {tag: tags.number, color: 'var(--syntax-number)'}, {tag: tags.comment, color: 'var(--muted)'}, {tag: tags.operator, color: 'var(--text)'},
])
const permissions = () => [EditorState.readOnly.of(!!props.readonly || !!props.disabled), EditorView.editable.of(!props.disabled && !props.readonly)]
function updateDiagnostics() { if (view) view.dispatch(setDiagnostics(view.state, diagnostics.value)) }
function locate(from: number) { if (view) { view.dispatch({selection: {anchor: Math.min(from, view.state.doc.length)}, scrollIntoView: true}); view.focus() } }
onMounted(() => {
  if (!element.value) return
  view = new EditorView({parent: element.value, doc: props.modelValue, extensions: [
    lineNumbers(), highlightActiveLine(), history(), keymap.of([...defaultKeymap, ...historyKeymap]),
    language, syntaxHighlighting(colors), lintGutter(), access.of(permissions()), EditorView.lineWrapping,
    EditorView.contentAttributes.of({'aria-label': props.label, role: 'textbox', 'aria-multiline': 'true', spellcheck: 'false'}),
    EditorView.updateListener.of(update => { if (update.docChanged && !external) emit('update:modelValue', update.state.doc.toString()) }),
  ]})
  updateDiagnostics()
})
watch(() => props.modelValue, text => {
  if (view && text !== view.state.doc.toString()) { external = true; view.dispatch({changes: {from: 0, to: view.state.doc.length, insert: text}}); external = false }
  updateDiagnostics()
})
watch(() => [props.disabled, props.readonly], () => view?.dispatch({effects: access.reconfigure(permissions())}))
onScopeDispose(() => view?.destroy())
</script>
<template>
  <div class="rule-editor" :class="{'rule-editor-disabled': disabled}">
    <div ref="element" class="rule-editor-input" />
    <div v-if="!readonly" class="rule-editor-status" aria-live="polite">
      <span :class="diagnostics.length ? 'rule-editor-error' : ''">{{diagnostics.length ? `${diagnostics.length} 处基础检查问题` : '基础检查通过'}} · {{modelValue.split('\n').length}} 行</span>
      <small>关键词、变量与引擎兼容性以目标探针的原生装载检查为准。</small>
    </div>
    <ul v-if="!readonly && diagnostics.length" class="rule-editor-problems"><li v-for="(problem,index) in diagnostics.slice(0,5)" :key="index"><button type="button" :disabled="disabled" @click="locate(problem.from)">第 {{problem.line}} 行：{{problem.message}}</button></li><li v-if="diagnostics.length>5">其余问题可在编辑器标记处查看。</li></ul>
  </div>
</template>
<style>
.rule-editor {border:1px solid var(--control-border);border-radius:6px;overflow:hidden;background:var(--surface);min-width:0;color:var(--text)}
.rule-editor:focus-within {outline:2px solid var(--primary);outline-offset:2px}
.rule-editor-input .cm-editor {font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;line-height:1.65;background:var(--surface);color:var(--text)}
.rule-editor-input .cm-scroller {min-height:180px;max-height:340px;overflow:auto}
.rule-editor-input .cm-content {padding:8px 0;min-width:0;overflow-wrap:anywhere;caret-color:var(--primary)}
.rule-editor-input .cm-gutters {background:var(--table-header);color:var(--muted);border-right:1px solid var(--line)}
.rule-editor-input .cm-activeLine,.rule-editor-input .cm-activeLineGutter {background:var(--table-header)}
.rule-editor-input .cm-focused {outline:none}
.rule-editor-input .cm-tooltip {background:var(--surface);color:var(--text);border-color:var(--control-border);max-width:min(500px,80vw)}
.rule-editor-input .cm-lintRange-error {text-decoration:underline wavy var(--danger)}
.rule-editor-status {display:flex;flex-wrap:wrap;gap:4px 12px;padding:8px 12px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}
.rule-editor-status small {font-size:12px}
.rule-editor-error,.rule-editor-problems {color:var(--danger)}
.rule-editor-problems {margin:0;padding:0 12px 8px 30px;font-size:12px}
.rule-editor-problems button {border:0;padding:2px 0;background:transparent;color:var(--danger);text-align:left;cursor:pointer}
.rule-editor-disabled {background:var(--table-header)}
</style>

<style>.rule-editor-input .cm-selectionBackground {background:var(--selection-surface)!important}</style>
