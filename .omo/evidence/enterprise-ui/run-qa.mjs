import { chromium } from '../../../dashboard/node_modules/playwright/index.mjs'
import { mkdir, writeFile } from 'node:fs/promises'

const baseUrl = 'http://127.0.0.1:5173'
const outputDir = '/home/wonka/Documents/ADSIEM/.omo/evidence/enterprise-ui'

const user = {
  id: 'qa-admin',
  username: 'qa-admin',
  email: 'qa@example.test',
  role: 'superadmin',
  group_id: null,
  is_active: true,
}

const agent = {
  id: 'agent-001',
  hostname: 'prod-edge-01',
  status: 'online',
  group_id: 'default',
  log_sources: [],
  os: 'linux',
  version: '1.8.0',
  ip_address: '10.20.4.18',
  last_seen: '2026-09-05T05:30:00Z',
  created_at: '2026-08-10T03:00:00Z',
}

const alert = {
  id: 'alert-001',
  title: 'Privileged authentication anomaly',
  description: 'Repeated privileged logins from a new network segment.',
  severity: 'high',
  status: 'new',
  source_ip: '198.51.100.42',
  destination_ip: '10.20.4.18',
  hostname: 'prod-edge-01',
  agent_id: agent.id,
  rule_id: 'AUTH-042',
  created_at: '2026-09-05T05:28:00Z',
  notes: [],
}

const securityCase = {
  id: 'case-001',
  case_number: 'CASE-2026-0142',
  title: 'Privileged access investigation',
  description: 'Validate a privileged login from a newly observed source.',
  severity: 'high',
  status: 'open',
  priority: 'high',
  group_id: 'default',
  alert_id: alert.id,
  assignee_id: user.id,
  assignee: user,
  created_at: '2026-09-05T05:29:00Z',
  updated_at: '2026-09-05T05:31:00Z',
  notes: [],
  ioc_data: { source_ip: alert.source_ip },
  search_intel: { results: [] },
}

const paged = (items = []) => ({ total: items.length, page: 1, page_size: 25, items })

function mockBody(url) {
  const { pathname } = new URL(url)

  if (pathname === '/api/auth/me') return user
  if (pathname === '/api/auth/refresh') return { access_token: 'qa-token' }
  if (pathname === '/api/search') return { alerts: [alert], cases: [securityCase] }

  if (pathname === '/api/agents/packages') return []
  if (pathname === '/api/agents/agent-001/log-sources') return []
  if (pathname === '/api/agents/agent-001') return agent
  if (pathname === '/api/agents') return paged([agent])

  if (pathname === '/api/alerts/alert-001/source-log') return null
  if (pathname === '/api/alerts/alert-001/feedback') return null
  if (pathname === '/api/alerts/alert-001') return alert
  if (pathname === '/api/alerts') return paged([alert])

  if (pathname === '/api/cases/case-001/timeline') return { items: [] }
  if (pathname === '/api/cases/case-001/feedback') return null
  if (pathname === '/api/cases/case-001') return securityCase
  if (pathname === '/api/cases') return paged([securityCase])

  if (pathname === '/api/events') return paged([])
  if (pathname === '/api/logs') return paged([])
  if (pathname === '/api/rules') return paged([])
  if (pathname === '/api/decoders') return paged([])
  if (pathname === '/api/users') return paged([user])
  if (pathname === '/api/webhooks') return paged([])
  if (pathname === '/api/audit-logs') return []

  if (pathname === '/api/settings') return []
  if (pathname === '/api/suppressions') return []
  if (pathname === '/api/hunt-schedules') return []
  if (pathname === '/api/hunts') return []
  if (pathname === '/api/fleet-hunts') return []
  if (pathname === '/api/tasks') return []

  if (pathname === '/api/hygiene/latest') return []
  if (pathname === '/api/ueba/entities') return []
  if (pathname === '/api/ueba/status') return { model_trained: true, user_snapshot_count: 124, ip_snapshot_count: 217 }
  if (pathname === '/api/fim/events') return []
  if (pathname === '/api/fim/paths') return []

  if (pathname === '/api/artifacts' || pathname === '/api/artifacts/builtins') return []
  if (pathname === '/api/yara-rules') return []
  if (pathname === '/api/soar/playbooks') return []
  if (pathname === '/api/sop-documents') return []
  if (pathname === '/api/handover') return []

  if (pathname === '/api/metrics/soc') {
    return { mean_time_to_acknowledge: 8, mean_time_to_resolve: 46, open_alerts: 12, open_cases: 4 }
  }
  if (pathname === '/api/metrics/workload') return []
  if (pathname.startsWith('/api/metrics/ti/')) return {}
  if (pathname === '/api/mitre/heatmap') {
    return { period_days: 90, total_alerts_with_mitre: 0, total_technique_hits: 0, max_count: 0, tactics: [] }
  }

  return {}
}

async function installApiMocks(page) {
  await page.route('**/api/**', async (route) => {
    const request = route.request()
    if (!new URL(request.url()).pathname.startsWith('/api/')) {
      await route.continue()
      return
    }
    if (request.resourceType() === 'websocket') {
      await route.abort()
      return
    }

    const body = mockBody(request.url())
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    })
  })
}

const routes = [
  ['dashboard', '/'],
  ['agents', '/agents'],
  ['agent-sources', '/agents/agent-001/sources'],
  ['logs', '/logs'],
  ['events', '/events'],
  ['alerts', '/alerts'],
  ['cases', '/cases'],
  ['case-detail', '/cases/case-001'],
  ['rules', '/rules'],
  ['decoders', '/decoders'],
  ['users', '/users'],
  ['webhooks', '/webhooks'],
  ['settings', '/settings'],
  ['hygiene', '/hygiene'],
  ['ueba', '/ueba'],
  ['fim', '/fim'],
  ['hunts', '/hunts'],
  ['reports', '/reports'],
  ['mitre-heatmap', '/mitre-heatmap'],
  ['live-response', '/live-response'],
  ['yara', '/yara'],
  ['soar', '/soar'],
  ['audit-logs', '/audit-logs'],
]

const viewports = [
  ['mobile', { width: 375, height: 812 }],
  ['tablet', { width: 768, height: 900 }],
  ['desktop', { width: 1280, height: 900 }],
]

await mkdir(outputDir, { recursive: true })
const browser = await chromium.launch({
  executablePath: '/usr/bin/chromium',
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage'],
})

const report = []

try {
  for (const [viewportName, viewport] of viewports) {
    const loginContext = await browser.newContext({ viewport })
    const loginPage = await loginContext.newPage()
    const loginErrors = []
    loginPage.on('pageerror', (error) => loginErrors.push(error.message))
    await installApiMocks(loginPage)
    await loginPage.goto(`${baseUrl}/login`, { waitUntil: 'domcontentloaded' })
    await loginPage.waitForSelector('#root > *:not(style)', { timeout: 10_000 })
    await loginPage.waitForTimeout(250)
    await loginPage.evaluate(() => document.fonts.ready)
    await loginPage.screenshot({ path: `${outputDir}/login-${viewportName}.png`, fullPage: true })
    report.push({ viewport: viewportName, route: '/login', pageErrors: loginErrors })
    await loginContext.close()

    const context = await browser.newContext({ viewport })
    await context.addInitScript(({ persistedUser }) => {
      localStorage.setItem('siem-auth', JSON.stringify({
        state: { accessToken: 'qa-token', user: persistedUser },
        version: 0,
      }))
    }, { persistedUser: user })

    for (const [name, path] of routes) {
      const page = await context.newPage()
      const pageErrors = []
      page.on('pageerror', (error) => pageErrors.push(error.message))
      await installApiMocks(page)
      await page.goto(`${baseUrl}${path}`, { waitUntil: 'domcontentloaded' })
      await page.waitForTimeout(2_000)
      await page.evaluate(() => document.fonts.ready)

      const audit = await page.evaluate(() => {
        const viewportWidth = document.documentElement.clientWidth
        const overflowElements = [...document.querySelectorAll('*')]
          .filter((element) => {
            const rect = element.getBoundingClientRect()
            const style = getComputedStyle(element)
            const scrollContainer = element.closest('.overflow-auto, .overflow-x-auto, [style*="overflowX: auto"], [style*="overflow-x: auto"]')
            return rect.right > viewportWidth + 1 && style.position !== 'fixed' && !scrollContainer
          })
          .slice(0, 8)
          .map((element) => ({
            tag: element.tagName.toLowerCase(),
            className: typeof element.className === 'string' ? element.className : '',
            right: Math.round(element.getBoundingClientRect().right),
          }))

        const unnamedButtons = [...document.querySelectorAll('button')]
          .filter((button) => !(button.textContent?.trim() || button.getAttribute('aria-label') || button.getAttribute('title')))
          .length

        return {
          title: document.title,
          h1: document.querySelectorAll('h1').length,
          horizontalOverflow: document.documentElement.scrollWidth > viewportWidth + 1,
          overflowElements,
          unnamedButtons,
          bodyTextLength: document.body.innerText.trim().length,
        }
      })

      await page.screenshot({ path: `${outputDir}/${name}-${viewportName}.png`, fullPage: true })
      report.push({ viewport: viewportName, route: path, pageErrors, ...audit })
      await page.close()
    }
    await context.close()
  }
} finally {
  await browser.close()
}

const failures = report.filter((item) =>
  item.pageErrors.length > 0 || item.horizontalOverflow || item.unnamedButtons > 0 || item.bodyTextLength === 0
)

await writeFile(`${outputDir}/qa-report.json`, `${JSON.stringify({ checked: report.length, failures, results: report }, null, 2)}\n`)

console.log(JSON.stringify({ checked: report.length, failures }, null, 2))
if (failures.length > 0) process.exitCode = 1
