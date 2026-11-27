import { useState } from 'react'
import type { FormEvent } from 'react'
import { format, isPast } from 'date-fns'
import { Trash2, UserCheck, UserMinus } from 'lucide-react'
import { QueryState } from '@/components/Workspace'
import { useAuthStore } from '@/stores/auth'
import { useCaseTasks, useCreateCaseTask, useDeleteCaseTask, useUpdateCaseTask } from '@/hooks/useCaseTasks'
import type { CaseTask } from '@/hooks/useCaseTasks'

function owner(task: CaseTask, me: string | undefined) {
  if (!task.assignee_id) return 'Unassigned'
  return task.assignee_id === me ? 'You' : `User ${task.assignee_id.slice(0, 8)}`
}

export default function CaseTasks({ caseId }: { readonly caseId: string }) {
  const { user, hasRole } = useAuthStore()
  const canManage = hasRole('analyst')
  const tasks = useCaseTasks(caseId)
  const create = useCreateCaseTask(caseId)
  const update = useUpdateCaseTask(caseId)
  const remove = useDeleteCaseTask(caseId)
  const [title, setTitle] = useState('')
  const [due, setDue] = useState('')
  const [mine, setMine] = useState(true)

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!title.trim()) return
    create.mutate({
      title: title.trim(),
      assignee_id: mine && user?.id ? user.id : undefined,
      due_at: due ? new Date(due).toISOString() : undefined,
    }, { onSuccess: () => { setTitle(''); setDue('') } })
  }

  if (tasks.isPending) return <QueryState kind="loading" title="Loading tasks…" description="Fetching this case's tasks." />
  if (tasks.isError) return <QueryState kind="error" title="Could not load tasks" description="Try again in a moment."
    onRetry={() => { void tasks.refetch() }} />
  const open = tasks.data.filter(task => !task.done).length

  return (
    <div className="case-tasks">
      <p className="table-secondary case-tasks__summary">{open} open · {tasks.data.length - open} done</p>
      {tasks.data.length === 0
        ? <QueryState kind="empty" title="No tasks yet" description="Break the response into steps and give each one an owner." />
        : <ul className="case-tasks__list">{tasks.data.map(task => {
          const overdue = !task.done && task.due_at && isPast(new Date(task.due_at))
          return (
            <li key={task.id} className={`case-task ${task.done ? 'case-task--done' : ''}`}>
              <input type="checkbox" className="alert-check" checked={task.done} disabled={!canManage || update.isPending}
                aria-label={`Mark "${task.title}" ${task.done ? 'not done' : 'done'}`}
                onChange={() => update.mutate({ id: task.id, change: { done: !task.done } })} />
              <div className="case-task__body">
                <span className="case-task__title">{task.title}</span>
                <span className="table-secondary">
                  {owner(task, user?.id)}
                  {task.due_at && <> · <span className={overdue ? 'case-task__overdue' : undefined}>
                    {overdue ? 'Overdue, ' : 'Due '}{format(new Date(task.due_at), 'dd MMM, HH:mm')}</span></>}
                  {task.done && task.completed_at && <> · done {format(new Date(task.completed_at), 'dd MMM, HH:mm')}</>}
                </span>
              </div>
              {canManage && <div className="control-cluster">
                {task.assignee_id === user?.id
                  ? <button className="ui-icon-button" title="Unassign" aria-label={`Unassign "${task.title}"`}
                    onClick={() => update.mutate({ id: task.id, change: { clear_assignee: true } })}><UserMinus size={15} /></button>
                  : user?.id && <button className="ui-icon-button" title="Assign to me" aria-label={`Assign "${task.title}" to me`}
                    onClick={() => update.mutate({ id: task.id, change: { assignee_id: user.id } })}><UserCheck size={15} /></button>}
                <button className="ui-icon-button" title="Delete task" aria-label={`Delete "${task.title}"`}
                  disabled={remove.isPending} onClick={() => remove.mutate(task.id)}><Trash2 size={15} /></button>
              </div>}
            </li>
          )
        })}</ul>}
      {canManage && <form className="case-tasks__form" onSubmit={submit}>
        <label className="field case-tasks__title"><span>New task</span>
          <input className="ui-input" value={title} maxLength={300} placeholder="e.g. Reset the user's password"
            onChange={event => setTitle(event.target.value)} /></label>
        <label className="field"><span>Due</span>
          <input className="ui-input" type="datetime-local" value={due} onChange={event => setDue(event.target.value)} /></label>
        <label className="alert-bulk__all"><input type="checkbox" className="alert-check" checked={mine}
          onChange={() => setMine(value => !value)} /> Assign to me</label>
        <button className="ui-button ui-button--primary" type="submit" disabled={create.isPending || !title.trim()}>
          {create.isPending ? 'Adding…' : 'Add task'}</button>
      </form>}
    </div>
  )
}
