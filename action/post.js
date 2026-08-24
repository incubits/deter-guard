// Runs at the end of the job, whether it passed, failed or was cancelled.
//
// This is why the action is JavaScript rather than composite, and it is not tidying-up. Two things
// only happen here:
//
//   1. The guard flushes its refusal report on SIGTERM. A guard the runner reaps instead enforces
//      perfectly and tells the console NOTHING — you keep the enforcement and lose the evidence for
//      it, which is the failure mode nobody notices because the build result looks identical.
//
//   2. The refusals get printed. A detached guard writes to a log file, and the build itself only
//      ever says something like `403 Forbidden`. Without this step, adopting the guard would make
//      every refusal HARDER to diagnose, not easier.
//
// Node built-ins only. See main.js.

'use strict'

const fs = require('node:fs')
const path = require('node:path')

const temp = process.env.RUNNER_TEMP || process.env.TMPDIR || '/tmp'
const stateDir = path.join(temp, 'deter-guard')
const statePath = path.join(stateDir, 'deter-guard.json')
const logPath = path.join(stateDir, 'deter-guard.log')

function log(msg) {
  process.stdout.write(`${msg}\n`)
}

function sleep(ms) {
  // Synchronous on purpose: the process must not exit before the guard has flushed.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

function stopGuard() {
  let pid
  try {
    pid = JSON.parse(fs.readFileSync(statePath, 'utf8')).pid
  } catch {
    return // never started, or already cleaned up
  }
  if (!pid) return

  try {
    process.kill(pid, 'SIGTERM')
  } catch {
    return // already gone
  }

  // The guard caps its own flush at 20s; wait a little past that rather than racing it.
  for (let i = 0; i < 25; i++) {
    try {
      process.kill(pid, 0)
    } catch {
      return // exited cleanly, report flushed
    }
    sleep(1000)
  }
  log('::warning title=deter-guard::the guard did not exit within 25s; its report may be incomplete')
}

function reportRefusals() {
  let contents
  try {
    contents = fs.readFileSync(logPath, 'utf8')
  } catch {
    return
  }

  log('::group::deter-guard log')
  process.stdout.write(contents.endsWith('\n') ? contents : `${contents}\n`)
  log('::endgroup::')

  // Deduplicated: one misconfigured host produces one annotation, not one per request. A wall of
  // identical annotations is the same as none.
  const refusals = [...new Set(
    contents.split('\n').filter((l) => /^deter-guard: (DENY|BLOCK)\b/.test(l)),
  )]
  for (const line of refusals) {
    log(`::error title=Egress refused::${line.replace(/^deter-guard: /, '')}`)
  }
  if (refusals.length > 0) {
    log(`::notice title=deter-guard::${refusals.length} host(s) were refused by your egress policy. ` +
        'Permit them in the deter console if they are legitimate — do not disable the guard.')
  }
}

stopGuard()
reportRefusals()
