import { useState } from 'react'
import DataTable from '@/components/DataTable'
import StatusBadge from '@/components/StatusBadge'
import { useUsers, useCreateUser, useDeleteUser } from '@/hooks/useUsers'
import { Plus, Trash2 } from 'lucide-react'
import type { User } from '@/types'

export default function UsersPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const { data, isLoading } = useUsers(page, pageSize)
  const createUser = useCreateUser()
  const deleteUser = useDeleteUser()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ username: '', email: '', password: '', role_id: 4, group_id: 'default' })

  const handleCreate = () => {
    createUser.mutate(form)
    setShowForm(false)
    setForm({ username: '', email: '', password: '', role_id: 4, group_id: 'default' })
  }

  const columns = [
    { key: 'username', header: 'Username', render: (r: User) => r.username },
    { key: 'email', header: 'Email', render: (r: User) => r.email },
    { key: 'role', header: 'Role', render: (r: User) => r.role },
    { key: 'group', header: 'Group', render: (r: User) => r.group_id },
    { key: 'active', header: 'Active', render: (r: User) => <StatusBadge status={r.is_active ? 'online' : 'offline'} /> },
    { key: 'actions', header: '', render: (r: User) => (
      <button onClick={() => deleteUser.mutate(r.id)} className="text-destructive hover:opacity-70">
        <Trash2 size={14} /></button>
    )},
  ]

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Users</h1>
        <button onClick={() => setShowForm(true)}
          className="flex items-center gap-1 px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">
          <Plus size={14} /> New User
        </button>
      </div>
      {showForm && (
        <div className="mb-4 p-4 rounded border border-border bg-card space-y-3">
          <div className="grid grid-cols-2 gap-3">
            {(['username', 'email', 'password', 'group_id'] as const).map((f) => (
              <div key={f}>
                <label className="block text-xs mb-1 capitalize">{f.replace('_', ' ')}</label>
                <input type={f === 'password' ? 'password' : 'text'} value={form[f] as string}
                  onChange={(e) => setForm((p) => ({ ...p, [f]: e.target.value }))}
                  className="w-full px-3 py-1.5 rounded border border-border bg-background text-sm" />
              </div>
            ))}
          </div>
          <div>
            <label className="block text-xs mb-1">Role</label>
            <select value={form.role_id} onChange={(e) => setForm((p) => ({ ...p, role_id: Number(e.target.value) }))}
              className="px-3 py-1.5 rounded border border-border bg-background text-sm">
              <option value={1}>superadmin</option>
              <option value={2}>admin</option>
              <option value={3}>analyst</option>
              <option value={4}>viewer</option>
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={handleCreate} className="px-4 py-1.5 rounded bg-primary text-primary-foreground text-sm">Create</button>
            <button onClick={() => setShowForm(false)} className="px-4 py-1.5 rounded border border-border text-sm">Cancel</button>
          </div>
        </div>
      )}
      {isLoading ? <div className="text-muted-foreground">Loading...</div> : (
        <DataTable columns={columns} data={data?.items ?? []} total={data?.total ?? 0}
          page={page} pageSize={pageSize} onPageChange={setPage}
          onPageSizeChange={(s) => { setPageSize(s); setPage(1) }} />
      )}
    </div>
  )
}
