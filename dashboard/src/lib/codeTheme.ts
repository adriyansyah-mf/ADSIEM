// CodeMirror theme for the canvas design: the rule editor's colours from the
// redesign (keys blue, strings yellow on a near-black ground, IBM Plex Mono).
import { EditorView } from 'codemirror'
import { HighlightStyle, syntaxHighlighting } from '@codemirror/language'
import { tags as t } from '@lezer/highlight'

const C = {
  ground: '#07090C', text: '#C9D0DB', muted: '#6B7586', key: '#9DB4FF', string: '#F2D45C',
  literal: '#C792EA', punct: '#8A94A6', line: '#10141C', select: '#24314F', caret: '#E8ECF2',
}

const view = EditorView.theme({
  '&': { backgroundColor: C.ground, color: C.text, fontSize: '12px', height: '100%' },
  '.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.7' },
  '.cm-content': { caretColor: C.caret, padding: '14px 0' },
  '.cm-cursor, .cm-dropCursor': { borderLeftColor: C.caret },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground, ::selection': { backgroundColor: C.select },
  '.cm-activeLine': { backgroundColor: C.line },
  '.cm-gutters': { backgroundColor: C.ground, color: '#4A5263', border: 'none' },
  '.cm-activeLineGutter': { backgroundColor: C.line, color: C.punct },
  '.cm-matchingBracket': { backgroundColor: '#1C2740', outline: '1px solid #3A4766' },
  '.cm-foldPlaceholder': { backgroundColor: '#1E222B', border: 'none', color: C.punct },
  '.cm-tooltip': { backgroundColor: '#14171E', border: '1px solid #262B36', color: C.text },
  '.cm-panels': { backgroundColor: '#14171E', color: C.text },
}, { dark: true })

const highlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName), t.labelName, t.attributeName], color: C.key },
  { tag: [t.string, t.special(t.string)], color: C.string },
  { tag: t.content, color: C.text },
  { tag: [t.number, t.bool, t.null, t.atom, t.keyword], color: C.literal },
  { tag: [t.comment, t.lineComment, t.blockComment], color: C.muted, fontStyle: 'italic' },
  { tag: [t.punctuation, t.separator, t.bracket, t.squareBracket, t.brace, t.meta], color: C.punct },
  { tag: [t.typeName, t.tagName, t.modifier], color: C.literal },
  { tag: t.invalid, color: '#FF8D98' },
])

export const canvasCodeTheme = [view, syntaxHighlighting(highlight)]
