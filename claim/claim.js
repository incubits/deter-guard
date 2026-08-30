// Settles a claim: proves to the console which organization owns this pipeline.
//
// The token GitHub mints for this job is the whole proof — there is nothing to paste back into the
// console, and nothing here is stored. See claim/action.yml for why this is its own action.
//
// Node built-ins only, like everything else in this repository. What you review here is what runs.

'use strict'

const path = require('node:path')
const { spawnSync } = require('node:child_process')

const inputs = require('../action/inputs.js')
const { fetchGuard } = require('../action/image.js')

const input = (name) => inputs.input(process.env, name)
const bool = (name) => inputs.bool(process.env, name)

function log(msg) {
  process.stdout.write(`${msg}\n`)
}

function fail(msg, code = 1) {
  // An annotation as well as a non-zero exit, so the reason lands on the run summary rather than
  // only in the step log.
  process.stdout.write(`::error title=deter-guard::${msg}\n`)
  process.exit(code)
}

function main() {
  // Not `input('console')`: the action.yml default only applies to the version a caller resolved,
  // and this is the first thing a new customer ever runs. See inputs.js.
  const consoleURL = inputs.consoleURL(process.env)

  const temp = process.env.RUNNER_TEMP || process.env.TMPDIR || '/tmp'
  const image = inputs.imageFor(process.env)

  let guard
  try {
    guard = fetchGuard({
      image,
      token: input('token'),
      verifyAttestation: bool('verify-attestation'),
      binDir: path.join(temp, 'deter-guard-bin'),
      log,
    })
  } catch (err) {
    fail(`could not obtain the guard from ${image}: ${err.message}`)
  }

  const env = { ...process.env, DETER_CONSOLE_URL: consoleURL }
  if (input('audience')) env.DETER_CI_OIDC_AUDIENCE = input('audience')
  if (input('project')) env.DETER_PROJECT = input('project')
  env.DETER_RUN_ID = input('run-id') || process.env.GITHUB_RUN_ID || ''

  const done = spawnSync(guard, ['claim'], { stdio: ['ignore', 'inherit', 'inherit'], env })
  if (done.status !== 0) {
    // The guard has already printed what is wrong and how to fix it — a missing `id-token: write`,
    // an organization nobody has claimed, an identity nothing signed. Repeating it here would just
    // bury it. Its exit code is passed straight through so a pipeline can still tell 3 (auth) from
    // 1 (configuration) without reading the log.
    fail('this pipeline could not prove which organization it belongs to; see the log above',
      done.status === null ? 1 : done.status)
  }
}

main()
