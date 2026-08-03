import { useState } from 'react'
import { ThumbsUp, ThumbsDown } from 'lucide-react'
import type { AiFeedback } from '@/types'

const VERDICT_OPTIONS = ['escalate', 'create_case', 'monitor', 'false_positive']

export default function AiFeedbackWidget({
  aiVerdict, feedback, isLoading, onSubmit, isSubmitting,
}: {
  aiVerdict: string | null | undefined
  feedback: AiFeedback[] | undefined
  isLoading: boolean
  onSubmit: (body: { rating: 'correct' | 'incorrect'; correct_verdict?: string; note?: string }) => void
  isSubmitting: boolean
}) {
  const [showIncorrectForm, setShowIncorrectForm] = useState(false)
  const [correctVerdict, setCorrectVerdict] = useState('')
  const [note, setNote] = useState('')

  if (isLoading) return null

  const latest = feedback && feedback.length > 0 ? feedback[0] : null

  if (latest) {
    return (
      <div className="flex items-center gap-2 text-xs text-muted-foreground mt-2 pt-2 border-t border-border">
        {latest.rating === 'correct' ? (
          <><ThumbsUp size={12} className="text-emerald-500" /> Marked correct by an analyst</>
        ) : (
          <>
            <ThumbsDown size={12} className="text-red-500" /> Marked incorrect
            {latest.correct_verdict ? ` — should have been "${latest.correct_verdict}"` : ''}
            {latest.note ? `: ${latest.note}` : ''}
          </>
        )}
      </div>
    )
  }

  return (
    <div className="mt-2 pt-2 border-t border-border">
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">Was this AI verdict{aiVerdict ? ` ("${aiVerdict}")` : ''} correct?</span>
        <button
          onClick={() => onSubmit({ rating: 'correct' })}
          disabled={isSubmitting}
          className="flex items-center gap-1 px-2 py-0.5 rounded border border-emerald-600/40 text-emerald-500 text-xs hover:bg-emerald-900/20 disabled:opacity-50"
        >
          <ThumbsUp size={11} /> Correct
        </button>
        <button
          onClick={() => setShowIncorrectForm(s => !s)}
          disabled={isSubmitting}
          className="flex items-center gap-1 px-2 py-0.5 rounded border border-red-600/40 text-red-500 text-xs hover:bg-red-900/20 disabled:opacity-50"
        >
          <ThumbsDown size={11} /> Incorrect
        </button>
      </div>
      {showIncorrectForm && (
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <select
            value={correctVerdict}
            onChange={e => setCorrectVerdict(e.target.value)}
            className="px-2 py-1 rounded border border-border bg-background text-xs"
          >
            <option value="">Correct verdict (optional)</option>
            {VERDICT_OPTIONS.map(v => <option key={v} value={v}>{v}</option>)}
          </select>
          <input
            value={note}
            onChange={e => setNote(e.target.value)}
            placeholder="Why? (optional)"
            className="flex-1 min-w-[140px] px-2 py-1 rounded border border-border bg-background text-xs"
          />
          <button
            onClick={() => {
              onSubmit({ rating: 'incorrect', correct_verdict: correctVerdict || undefined, note: note || undefined })
              setShowIncorrectForm(false)
            }}
            disabled={isSubmitting}
            className="px-2 py-1 rounded bg-primary text-primary-foreground text-xs disabled:opacity-50"
          >
            Submit
          </button>
        </div>
      )}
    </div>
  )
}
