import { Handle, Position } from '@xyflow/react'
import type { Node, NodeProps } from '@xyflow/react'
import { NODE_META, summary } from '@/components/soar/meta'
import type { NodeType, Params } from '@/types/soar'

export type StepStatus = 'success' | 'error' | 'waiting'

export interface WfNodeData extends Record<string, unknown> {
  wfType: NodeType
  label: string
  params: Params
  status?: StepStatus | 'skipped'
  taken?: string | null
}

export type WfFlowNode = Node<WfNodeData, 'wf'>

const STATUS_COLOR: Record<StepStatus, string> = {
  success: 'var(--accent-green)',
  error: 'var(--accent-red)',
  waiting: 'var(--accent-yellow)',
}

export function WorkflowNode({ id, data, selected }: NodeProps<WfFlowNode>) {
  const meta = NODE_META[data.wfType]
  const Icon = meta.icon
  const outputs = meta.outputs
  const ring = data.status && data.status !== 'skipped' ? STATUS_COLOR[data.status] : selected ? meta.color : 'var(--border)'
  const height = Math.max(64, outputs.length * 22 + 20)

  return (
    <div style={{
      width: 230, minHeight: height, background: 'var(--bg-card)', borderRadius: 8,
      border: `1.5px solid ${ring}`, boxShadow: selected ? `0 0 0 3px ${meta.color}33` : 'none',
      opacity: data.status === 'skipped' ? 0.35 : 1, position: 'relative', paddingRight: outputs.length > 1 ? 54 : 10,
    }}>
      {data.wfType !== 'trigger' && (
        <Handle type="target" position={Position.Left}
          style={{ width: 10, height: 10, background: 'var(--bg-panel)', border: '2px solid var(--text-secondary)' }} />
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 10px 4px' }}>
        <span style={{ width: 24, height: 24, borderRadius: 6, background: `${meta.color}22`, color: meta.color,
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flex: '0 0 auto' }}>
          <Icon size={14} />
        </span>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap',
            overflow: 'hidden', textOverflow: 'ellipsis' }}>{data.label}</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>{id}</div>
        </div>
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', padding: '0 10px 9px', whiteSpace: 'nowrap',
        overflow: 'hidden', textOverflow: 'ellipsis' }} title={summary({ type: data.wfType, params: data.params })}>
        {summary({ type: data.wfType, params: data.params })}
      </div>

      {outputs.map((out, i) => {
        const top = `${((i + 1) / (outputs.length + 1)) * 100}%`
        const isErr = out === 'error' || out === 'rejected' || out === 'false' || out === 'no'
        const taken = data.taken === out
        return (
          <div key={out}>
            {outputs.length > 1 && (
              <span style={{ position: 'absolute', right: 12, top, transform: 'translateY(-50%)', fontSize: 10,
                fontWeight: taken ? 700 : 500, color: taken ? 'var(--accent-green)' : isErr ? '#ff6b81' : 'var(--text-secondary)' }}>
                {out}
              </span>
            )}
            <Handle type="source" position={Position.Right} id={out}
              style={{ top, width: 10, height: 10, background: isErr ? 'var(--accent-red)' : meta.color,
                border: '2px solid var(--bg-card)' }} />
          </div>
        )
      })}
    </div>
  )
}
