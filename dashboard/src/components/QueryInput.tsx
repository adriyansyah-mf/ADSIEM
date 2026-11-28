import { useMemo, useRef, type InputHTMLAttributes } from 'react'
import { tokenizeQuery } from '@/lib/queryHighlight'

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, 'value' | 'onChange'> & {
  value: string
  onChange: (value: string) => void
}

/**
 * A plain text input with the query's syntax colours drawn behind it: the
 * input's own text is transparent (the caret and selection stay), and a
 * layer with the same font shows field, operator and value colours. Typing,
 * paste, undo and screen readers all use the real input.
 */
export default function QueryInput({ value, onChange, className, ...rest }: Props) {
  const layer = useRef<HTMLDivElement>(null)
  const tokens = useMemo(() => tokenizeQuery(value), [value])
  const sync = (el: HTMLInputElement) => { if (layer.current) layer.current.scrollLeft = el.scrollLeft }

  return (
    <div className={`cv-qinput ${className ?? ''}`}>
      <div ref={layer} className="cv-qinput__layer" aria-hidden="true">
        {tokens.map((t, i) => t.kind === 'space' || t.kind === 'text'
          ? t.text
          : <span key={i} className={`cv-q-${t.kind}`}>{t.text}</span>)}
        {' '}
      </div>
      <input {...rest} value={value} className="cv-qinput__field"
        onChange={event => { onChange(event.target.value); sync(event.target) }}
        onScroll={event => sync(event.currentTarget)}
        onKeyUp={event => sync(event.currentTarget)}
        onSelect={event => sync(event.currentTarget)} />
    </div>
  )
}
