// Install one-liners for Agents → Deploy agent. Pure functions, so they can be
// run outside the browser (tests execute the generated commands).
import type { AgentPackage } from '@/types'

export type Target = 'deb' | 'rpm' | 'windows'

// single-quoted shell / PowerShell literal
const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`

// The first certificate of a PEM file, as single-line base64 DER.
export function firstCertB64(pem: string): string | null {
  const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/)
  return m ? m[1].replace(/\s+/g, '') : null
}

// Adds the platform's (self-signed) certificate to the host's trust store, so
// both the download below and the agent's own TLS checks accept the server.
export function trustCommand(target: Target, certB64: string): string {
  if (target === 'windows') {
    return [
      `$ca = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String(${q(certB64)}))`,
      "$st = [Security.Cryptography.X509Certificates.X509Store]::new('Root', 'LocalMachine'); $st.Open('ReadWrite'); $st.Add($ca); $st.Close()",
    ].join('\n')
  }
  const lines = ['-----BEGIN CERTIFICATE-----', ...(certB64.match(/.{1,64}/g) ?? []), '-----END CERTIFICATE-----']
  const pem = `printf '%s\\n' ${lines.map(q).join(' ')}`
  const install = target === 'deb'
    ? 'sudo tee /usr/local/share/ca-certificates/adsiem-platform.crt >/dev/null && sudo update-ca-certificates >/dev/null'
    : 'sudo tee /etc/pki/ca-trust/source/anchors/adsiem-platform.pem >/dev/null && sudo update-ca-trust extract'
  return `${pem} | ${install} && \\\n`
}

export function installCommand(target: Target, pkg: AgentPackage, server: string, key: string, name: string,
                               certB64: string | null = null): string {
  const trust = certB64 ? trustCommand(target, certB64) : ''
  const url = `${server}/api/agents/packages/${pkg.filename}`
  if (pkg.type === 'msi') {
    // same properties work for Intune / SCCM / any software deployment tool
    const props = [`SERVER_URL=${server}`, `ENROLLMENT_KEY=${key}`, 'ENABLE_AUDITING=1'].join(' ')
    return [
      '# elevated PowerShell',
      ...(trust ? [trust] : []),
      `$m = "$env:TEMP\\siem-agent.msi"; Invoke-WebRequest -UseBasicParsing ${q(url)} -OutFile $m`,
      `Start-Process msiexec.exe -Wait -ArgumentList "/i \`"$m\`" /qn ${props}"`,
    ].join('\n')
  }
  if (target === 'windows') {
    return [
      '# elevated PowerShell',
      ...(trust ? [trust] : []),
      `$z ="$env:TEMP\\siem-agent.zip"; Invoke-WebRequest -UseBasicParsing ${q(url)} -OutFile $z`,
      'Expand-Archive $z "$env:TEMP\\siem-agent" -Force',
      `powershell -ExecutionPolicy Bypass -File "$env:TEMP\\siem-agent\\install.ps1" -ServerUrl ${q(server)} -EnrollmentToken ${q(key)} -EnableAuditing`,
    ].join('\n')
  }
  const file = `/tmp/${pkg.filename}`
  const env = [`SIEM_SERVER_URL=${q(server)}`, `SIEM_ENROLLMENT_KEY=${q(key)}`, ...(name ? [`SIEM_AGENT_NAME=${q(name)}`] : [])].join(' ')
  const install = target === 'deb' ? `dpkg -i ${file}` : `rpm -Uvh ${file}`
  return `${trust}curl -fsSLo ${file} ${q(url)} && sudo ${env} ${install}`
}

export function isIpHost(url: string): boolean {
  try {
    return /^(\d{1,3}\.){3}\d{1,3}$|^\[/.test(new URL(url).hostname)
  } catch {
    return false
  }
}

export async function sha256Fingerprint(b64: string): Promise<string> {
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', der))
  return Array.from(digest, b => b.toString(16).padStart(2, '0').toUpperCase()).join(':')
}
