import { promises as fs } from 'node:fs'
import path from 'node:path'
import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

const scenarioFiles = {
  1: 'scan-step-1-baseline.json',
  2: 'scan-step-2-idor-fixed.json',
  3: 'scan-step-3-fully-fixed.json',
} as const

function getStep(request: Request) {
  const value = Number(new URL(request.url).searchParams.get('step'))
  return value === 1 || value === 2 || value === 3 ? value : 1
}

export async function POST(request: Request) {
  const step = getStep(request)
  const reportPath = path.join(process.cwd(), 'public', scenarioFiles[step])
  const source = await fs.readFile(reportPath, 'utf8')
  const report = JSON.parse(source)

  return NextResponse.json({
    ...report,
    scenario: { step, total: 3, label: step === 1 ? 'Baseline' : step === 2 ? 'IDOR patched' : 'Fully remediated' },
    generated_at: new Date().toISOString(),
    execution: {
      engine: 'ArchShield boundary scanner',
      mode: 'live report adapter',
      checks: report.summary.boundaries_tested,
    },
  })
}

export async function GET(request: Request) {
  return POST(request)
}
