import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  addEdge,
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowLeft, Save } from 'lucide-react'
import { PageHeader } from '@/components/ui/PageHeader'
import { ConfigPanel } from '@/components/soar-canvas/ConfigPanel'
import { NodePalette } from '@/components/soar-canvas/NodePalette'
import {
  saveErrorMessage,
  useNodeTypes,
  useSaveWorkflow,
  useWorkflow,
  type NodeTypeMeta,
  type WorkflowSavePayload,
} from '@/hooks/useSoarWorkflows'

interface SoarNodeData extends Record<string, unknown> {
  nodeType: string
  name: string
  config: Record<string, unknown>
  handles: string[]
  isDestructive: boolean
}

type SoarNode = Node<SoarNodeData, 'soar'>

function SoarNodeView({ data, selected }: NodeProps<SoarNode>) {
  const handles = data.handles.length > 0 ? data.handles : ['out']
  return (
    <div
      className={`min-w-[150px] rounded border px-3 py-2 text-[12px] ${
        selected ? 'border-[var(--accent-blue)]' : 'border-[var(--border)]'
      } bg-[var(--bg-panel)] text-[var(--text-primary)]`}
    >
      <Handle type="target" position={Position.Left} />
      <div className="font-semibold">{data.name}</div>
      <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{data.nodeType}</div>
      {data.isDestructive && (
        <div className="mt-1 text-[10px] font-bold uppercase text-[var(--accent-orange,#f59e0b)]">approval</div>
      )}
      {handles.map((handle, index) => (
        <Handle
          key={handle}
          id={handle}
          type="source"
          position={Position.Right}
          style={{ top: 18 + index * 14 }}
        />
      ))}
      {handles.length > 1 && (
        <div className="mt-1 flex flex-col items-end text-[9px] text-[var(--text-muted)]">
          {handles.map((handle) => <span key={handle}>{handle}</span>)}
        </div>
      )}
    </div>
  )
}

const nodeTypes = { soar: SoarNodeView }

export default function SoarCanvasPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: workflow, isLoading } = useWorkflow(id)
  const { data: catalogue = [] } = useNodeTypes()
  const save = useSaveWorkflow(id)

  const [nodes, setNodes, onNodesChange] = useNodesState<SoarNode>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const metaByType = useMemo(
    () => new Map(catalogue.map((meta) => [meta.node_type, meta])),
    [catalogue],
  )

  useEffect(() => {
    if (!workflow || catalogue.length === 0) return
    setNodes(
      workflow.nodes.map((node) => ({
        id: node.id,
        type: 'soar' as const,
        position: { x: node.pos_x, y: node.pos_y },
        data: {
          nodeType: node.node_type,
          name: node.name,
          config: node.config ?? {},
          handles: metaByType.get(node.node_type)?.handles ?? ['out'],
          isDestructive: metaByType.get(node.node_type)?.is_destructive ?? false,
        },
      })),
    )
    setEdges(
      workflow.edges.map((edge, index) => ({
        id: edge.id ?? `e${index}`,
        source: edge.source_node_id,
        target: edge.target_node_id,
        sourceHandle: edge.source_handle,
        label: edge.source_handle === 'out' ? undefined : edge.source_handle,
      })),
    )
  }, [workflow, catalogue.length, metaByType, setNodes, setEdges])

  const onConnect = useCallback(
    (connection: Connection) =>
      setEdges((current) =>
        addEdge(
          {
            ...connection,
            label: connection.sourceHandle && connection.sourceHandle !== 'out' ? connection.sourceHandle : undefined,
          },
          current,
        ),
      ),
    [setEdges],
  )

  function addNode(meta: NodeTypeMeta) {
    const newId = crypto.randomUUID()
    const existing = nodes.filter((n) => n.data.nodeType === meta.node_type).length
    setNodes((current) => [
      ...current,
      {
        id: newId,
        type: 'soar' as const,
        position: { x: 80 + current.length * 40, y: 80 + current.length * 60 },
        data: {
          nodeType: meta.node_type,
          name: existing === 0 ? meta.label : `${meta.label} ${existing + 1}`,
          config: {},
          handles: meta.handles,
          isDestructive: meta.is_destructive,
        },
      },
    ])
    setSelectedId(newId)
  }

  function updateSelected(patch: Partial<SoarNodeData>) {
    setNodes((current) =>
      current.map((node) => (node.id === selectedId ? { ...node, data: { ...node.data, ...patch } } : node)),
    )
  }

  function deleteSelected() {
    setNodes((current) => current.filter((node) => node.id !== selectedId))
    setEdges((current) => current.filter((edge) => edge.source !== selectedId && edge.target !== selectedId))
    setSelectedId(null)
  }

  function onSave() {
    if (!workflow) return
    setError(null)
    const payload: WorkflowSavePayload = {
      name: workflow.name,
      description: workflow.description,
      is_enabled: workflow.is_enabled,
      nodes: nodes.map((node) => ({
        id: node.id,
        node_type: node.data.nodeType,
        name: node.data.name,
        config: node.data.config,
        pos_x: node.position.x,
        pos_y: node.position.y,
      })),
      edges: edges.map((edge) => ({
        source_node_id: edge.source,
        source_handle: edge.sourceHandle || 'out',
        target_node_id: edge.target,
      })),
    }
    save.mutate(payload, { onError: (e) => setError(saveErrorMessage(e)) })
  }

  const selected = nodes.find((node) => node.id === selectedId)
  const selectedMeta = selected ? metaByType.get(selected.data.nodeType) : undefined

  if (isLoading) return <div className="p-4 text-sm text-[var(--text-muted)]">Loading workflow…</div>
  if (!workflow) return <div className="p-4 text-sm text-[var(--text-muted)]">Workflow not found.</div>

  return (
    <div className="flex h-[calc(100vh-90px)] flex-col">
      <PageHeader
        title={workflow.name}
        breadcrumb="Automation / SOAR"
        subtitle="Drag from a step's right edge to another step to connect them. Branching steps expose one output per branch."
        actions={
          <>
            <button
              type="button"
              onClick={() => navigate('/soar/workflows')}
              className="flex items-center gap-1.5 rounded border border-[var(--border)] px-3 py-1.5 text-[12px] text-[var(--text-secondary)]"
            >
              <ArrowLeft size={13} /> Back
            </button>
            <button
              type="button"
              onClick={onSave}
              disabled={save.isPending}
              className="flex items-center gap-1.5 rounded bg-[var(--accent-blue)] px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-60"
            >
              <Save size={13} /> {save.isPending ? 'Saving…' : 'Save'}
            </button>
          </>
        }
      />

      {error && (
        <div className="mb-2 rounded border border-red-500/50 bg-red-500/10 px-3 py-2 text-[12px] text-red-300">
          {error}
        </div>
      )}
      {save.isSuccess && !error && (
        <div className="mb-2 rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-[12px] text-emerald-300">
          Saved.
        </div>
      )}

      <div className="grid min-h-0 flex-1 grid-cols-[180px_minmax(0,1fr)_280px] gap-2">
        <div className="rounded border border-[var(--border)] bg-[var(--bg-panel)]">
          <NodePalette nodeTypes={catalogue} onAdd={addNode} />
        </div>

        <div className="rounded border border-[var(--border)] bg-[var(--bg-panel)]">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={(_, node) => setSelectedId(node.id)}
            onPaneClick={() => setSelectedId(null)}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>

        <div className="rounded border border-[var(--border)] bg-[var(--bg-panel)]">
          {selected && selectedMeta ? (
            <ConfigPanel
              meta={selectedMeta}
              name={selected.data.name}
              config={selected.data.config}
              onNameChange={(name) => updateSelected({ name })}
              onConfigChange={(config) => updateSelected({ config })}
              onDelete={deleteSelected}
            />
          ) : (
            <div className="p-4 text-[12px] leading-relaxed text-[var(--text-muted)]">
              Pick a step from the left to add it, then click a step on the canvas to configure it.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
