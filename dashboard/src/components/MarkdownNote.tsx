import ReactMarkdown from 'react-markdown'

interface Props {
  content: string
  className?: string
  style?: React.CSSProperties
}

export default function MarkdownNote({ content, className, style }: Props) {
  return (
    <div className={className} style={style}>
      <ReactMarkdown
        components={{
          p: ({ children }) => (
            <p style={{ margin: '0 0 8px 0', lineHeight: 1.65 }}>{children}</p>
          ),
          ul: ({ children }) => (
            <ul style={{ margin: '4px 0 8px 0', paddingLeft: '18px' }}>{children}</ul>
          ),
          ol: ({ children }) => (
            <ol style={{ margin: '4px 0 8px 0', paddingLeft: '18px' }}>{children}</ol>
          ),
          li: ({ children }) => (
            <li style={{ marginBottom: '3px', lineHeight: 1.55 }}>{children}</li>
          ),
          strong: ({ children }) => (
            <strong style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>{children}</strong>
          ),
          em: ({ children }) => (
            <em style={{ color: 'var(--text-secondary)' }}>{children}</em>
          ),
          code: ({ children }) => (
            <code style={{
              fontFamily: 'Share Tech Mono, monospace',
              fontSize: '11px',
              background: 'var(--bg-panel)',
              border: '1px solid var(--border)',
              borderRadius: '3px',
              padding: '1px 5px',
              color: 'var(--accent-yellow)',
            }}>{children}</code>
          ),
          blockquote: ({ children }) => (
            <blockquote style={{
              borderLeft: '3px solid var(--accent-cyan)',
              paddingLeft: '10px',
              margin: '6px 0',
              color: 'var(--text-secondary)',
              fontStyle: 'italic',
            }}>{children}</blockquote>
          ),
          h1: ({ children }) => (
            <h1 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '15px', letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--accent-cyan)', margin: '8px 0 4px 0' }}>{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '13px', letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--accent-cyan)', margin: '8px 0 4px 0' }}>{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 style={{ fontFamily: 'Rajdhani, sans-serif', fontWeight: 700, fontSize: '12px', letterSpacing: '1px', color: 'var(--text-secondary)', margin: '6px 0 3px 0' }}>{children}</h3>
          ),
          hr: () => (
            <hr style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '8px 0' }} />
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  )
}
