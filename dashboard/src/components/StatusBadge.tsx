const map: Record<string, string> = {
  new: 'bg-blue-600 text-white',
  in_progress: 'bg-yellow-500 text-black',
  resolved: 'bg-green-600 text-white',
  false_positive: 'bg-gray-500 text-white',
  online: 'bg-green-500 text-white',
  offline: 'bg-gray-600 text-white',
}
export default function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${map[status] ?? 'bg-gray-400 text-white'}`}>
      {status.replace('_', ' ')}
    </span>
  )
}
