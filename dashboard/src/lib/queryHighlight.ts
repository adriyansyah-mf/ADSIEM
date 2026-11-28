// Token kinds for the search query bar's syntax colours (Lucene-style:
// field:value, quoted strings, AND / OR / NOT, groups). The tokens' text joined
// is always the input itself, so the coloured layer lines up with the input.
export type QueryTokenKind = 'field' | 'colon' | 'value' | 'op' | 'paren' | 'text' | 'space'

export interface QueryToken {
  text: string
  kind: QueryTokenKind
}

const OPERATORS = new Set(['AND', 'OR', 'NOT', 'TO', '&&', '||'])
const BREAK = /[\s"()[\]{}]/

/** End of the quoted string starting at i (index past the closing quote, or the end). */
function stringEnd(q: string, i: number): number {
  let j = i + 1
  while (j < q.length) {
    if (q[j] === '\\') j += 2
    else if (q[j] === '"') return j + 1
    else j++
  }
  return q.length
}

/** End of the bracketed group starting at i (past its matching close, or the end). */
function groupEnd(q: string, i: number): number {
  const open = q[i]
  const close = open === '(' ? ')' : open === '[' ? ']' : '}'
  let depth = 0
  let j = i
  while (j < q.length) {
    const c = q[j]
    if (c === '"') { j = stringEnd(q, j); continue }
    if (c === open || (open !== '(' && (c === '[' || c === '{'))) depth++
    else if (c === close || (open !== '(' && (c === ']' || c === '}'))) {
      depth--
      if (depth === 0) return j + 1
    }
    j++
  }
  return q.length
}

export function tokenizeQuery(q: string): QueryToken[] {
  const out: QueryToken[] = []
  const push = (text: string, kind: QueryTokenKind) => { if (text) out.push({ text, kind }) }
  let i = 0
  while (i < q.length) {
    const c = q[i]
    if (/\s/.test(c)) {
      let j = i
      while (j < q.length && /\s/.test(q[j])) j++
      push(q.slice(i, j), 'space')
      i = j
    } else if (c === '"') {
      const j = stringEnd(q, i)
      push(q.slice(i, j), 'value')
      i = j
    } else if ('()[]{}'.includes(c)) {
      push(c, 'paren')
      i++
    } else {
      let j = i
      while (j < q.length && !BREAK.test(q[j])) {
        if (q[j] === '\\') j++
        j++
      }
      j = Math.min(j, q.length)
      const word = q.slice(i, j)
      const colon = word.search(/(?<!\\):/)
      if (colon > 0) {
        const prefix = /^[-+!]/.test(word) ? word[0] : ''
        push(prefix, 'op')
        push(word.slice(prefix.length, colon), 'field')
        push(':', 'colon')
        const rest = word.slice(colon + 1)
        if (rest) {
          push(rest, 'value')
        } else if (j < q.length && '"([{'.includes(q[j])) {
          // field:"…" or field:(a OR b) / field:[1 TO 5]: the whole group is the value
          const end = q[j] === '"' ? stringEnd(q, j) : groupEnd(q, j)
          push(q.slice(j, end), 'value')
          j = end
        }
      } else if (OPERATORS.has(word) || word === '!') {
        push(word, 'op')
      } else {
        push(word, 'text')
      }
      i = j
    }
  }
  return out
}
