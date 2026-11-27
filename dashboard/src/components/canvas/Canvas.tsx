import { createContext, useContext, useLayoutEffect, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { NAVIGATION, SETTINGS_SECTION, sectionFor, useVisiblePages } from '@/components/AppSidebar'

/** Lets a page tell the shell it draws its own header, so the shell's top bar steps aside on desktop. */
export const PageChromeContext = createContext<(ownHeader: boolean) => void>(() => undefined)

export interface CanvasTab {
  readonly to: string
  readonly label: string
  readonly count?: number | null
  /** Explicit state, for tabs that differ only by query string. */
  readonly active?: boolean
}

function groupLabel(key: string | undefined): string | null {
  if (!key) return null
  if (key === SETTINGS_SECTION.key) return 'Admin'
  return NAVIGATION.find(group => group.items.some(item => item.key === key))?.label ?? null
}

/** Page header as drawn on the canvas: breadcrumb, title, one-line context, actions, section tabs. */
export function CanvasHeader({ title, sub, actions, tabs, counts, crumb, children }: {
  readonly title: ReactNode
  readonly sub?: ReactNode
  readonly actions?: ReactNode
  /** Overrides the entry's sibling pages. */
  readonly tabs?: readonly CanvasTab[]
  /** Count shown next to a sibling page, keyed by route. */
  readonly counts?: Readonly<Record<string, number | null | undefined>>
  /** Overrides the last breadcrumb segment. */
  readonly crumb?: ReactNode
  readonly children?: ReactNode
}) {
  const setOwnHeader = useContext(PageChromeContext)
  const { pathname } = useLocation()
  const visible = useVisiblePages()
  const section = sectionFor(pathname)
  useLayoutEffect(() => {
    setOwnHeader(true)
    return () => setOwnHeader(false)
  }, [setOwnHeader])

  const links: readonly CanvasTab[] = tabs
    ?? (section ? visible(section).map(page => ({ to: page.to, label: page.label, count: counts?.[page.to] })) : [])
  const group = groupLabel(section?.key)

  return (
    <header className="cv-head">
      <nav aria-label="Breadcrumb" className="cv-crumb">
        {group && <>{group} / </>}<span>{crumb ?? section?.label ?? title}</span>
      </nav>
      <div className="cv-head__row">
        <div className="cv-head__title">
          <h1>{title}</h1>
          {sub && <p className="cv-sub">{sub}</p>}
        </div>
        {actions && <div className="cv-head__actions">{actions}</div>}
      </div>
      {children}
      {links.length > 1 && (
        <nav className="cv-tabs" aria-label={`${section?.label ?? 'Page'} sections`}>
          {links.map(link => (
            <NavLink key={link.to} to={link.to} end className={({ isActive }) => (link.active ?? isActive) ? 'is-active' : undefined}>
              {link.label}
              {link.count != null && <span className="cv-tabs__count">{link.count.toLocaleString('en-US')}</span>}
            </NavLink>
          ))}
        </nav>
      )}
    </header>
  )
}

/** Full-bleed page body that cancels the shell's content padding, like the canvas artboards. */
export function CanvasPage({ children, className = '' }: { readonly children: ReactNode; readonly className?: string }) {
  return <div className={`cv ${className}`}>{children}</div>
}

export interface Kpi {
  readonly label: string
  readonly value: ReactNode
  readonly note?: ReactNode
  readonly tone?: 'bad' | 'warn' | 'good' | 'info' | 'muted'
}

/** Joined KPI strip (1px gaps over the border colour). */
export function KpiStrip({ items, min = 160 }: { readonly items: readonly Kpi[]; readonly min?: number }) {
  return (
    <div className="cv-kpis" style={{ gridTemplateColumns: `repeat(auto-fit, minmax(${min}px, 1fr))` }}>
      {items.map(item => (
        <div key={item.label} className="cv-kpi">
          <p className="cv-kpi__label">{item.label}</p>
          <p className="cv-kpi__value">{item.value}</p>
          {item.note != null && <p className={`cv-kpi__note ${item.tone ? `is-${item.tone}` : ''}`}>{item.note}</p>}
        </div>
      ))}
    </div>
  )
}

export type Tone = 'bad' | 'warn' | 'info' | 'good' | 'muted' | 'yellow'

export function Chip({ tone = 'muted', children }: { readonly tone?: Tone; readonly children: ReactNode }) {
  return <span className={`cv-chip cv-chip--${tone}`}>{children}</span>
}

export function severityTone(severity: string | null | undefined): Tone {
  switch (severity) {
    case 'critical': return 'bad'
    case 'high': return 'warn'
    case 'medium': return 'yellow'
    case 'low': case 'info': return 'info'
    default: return 'muted'
  }
}

/** Segmented control (pressed button = current value). */
export function Seg<T extends string>({ value, options, onChange, label }: {
  readonly value: T
  readonly options: readonly { readonly value: T; readonly label: ReactNode }[]
  readonly onChange: (value: T) => void
  readonly label: string
}) {
  return (
    <div className="cv-seg" role="group" aria-label={label}>
      {options.map(option => (
        <button key={option.value} type="button" aria-pressed={option.value === value} onClick={() => onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** Thin horizontal meter, 0–100. */
export function Meter({ value, tone = 'info' }: { readonly value: number; readonly tone?: Tone }) {
  const width = Math.max(0, Math.min(100, value))
  return <span className="cv-meter"><span className={`cv-meter__fill cv-meter__fill--${tone}`} style={{ width: `${width}%` }} /></span>
}

/** Tiny bar sparkline, values scaled to their own max. */
export function Spark({ values, tone = 'info' }: { readonly values: readonly number[]; readonly tone?: Tone }) {
  const max = Math.max(1, ...values)
  return (
    <span className="cv-spark" aria-hidden="true">
      {values.map((value, index) => (
        <span key={index} className={`cv-spark__bar cv-meter__fill--${tone}`} style={{ height: `${Math.max(8, (value / max) * 100)}%` }} />
      ))}
    </span>
  )
}

export function SectionTitle({ children, action }: { readonly children: ReactNode; readonly action?: ReactNode }) {
  return (
    <div className="cv-h3row">
      <h3 className="cv-h3">{children}</h3>
      {action}
    </div>
  )
}

export function Empty({ children }: { readonly children: ReactNode }) {
  return <p className="cv-empty">{children}</p>
}
