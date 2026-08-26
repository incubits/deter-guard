// Starts the guard and points the rest of the job at it.
//
// Node built-ins only — no npm dependencies, no bundler, no node_modules. What is reviewed here is
// what runs on the runner, which is the minimum bar for a tool whose job is supply-chain control.
//
// Teardown lives in post.js, which GitHub runs automatically at the end of the job. See action.yml.

'use strict'

const { execFileSync, spawnSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const GUARD_REPO = 'incubits/deter-guard'

// See inputs.js for why these are a separate, tested module rather than two lines inlined here.
const inputs = require('./inputs.js')

const input = (name) => inputs.input(process.env, name)
const bool = (name) => inputs.bool(process.env, name)

function log(msg) {
  process.stdout.write(`${msg}\n`)
}

function fail(msg) {
  // An annotation as well as a non-zero exit, so the reason lands on the run summary rather than
  // only in the step log.
  process.stdout.write(`::error title=deter-guard::${msg}\n`)
  process.exit(1)
}

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts })
}

function main() {
  const consoleURL = input('console')
  const policyFile = input('policy')
  if (!consoleURL && !policyFile) {
    fail('set `console` to your deter console URL, or `policy` to a local policy file')
  }
  if (consoleURL && !input('pubkey')) {
    // Not fatal — the guard still verifies — but verifying a bundle against a key from the same
    // response proves only that it is internally consistent. Say so where somebody will see it.
    log('::warning title=deter-guard::no `pubkey` given, so the policy is verified against the key ' +
        'the console served. Pin it to make this a real check.')
  }

  const temp = process.env.RUNNER_TEMP || process.env.TMPDIR || '/tmp'
  const stateDir = path.join(temp, 'deter-guard')
  const binDir = path.join(temp, 'deter-guard-bin')
  fs.mkdirSync(stateDir, { recursive: true })
  fs.mkdirSync(binDir, { recursive: true })

  // Not `input('image')`: unset means "the image built from the same commit as this action", which
  // is what makes pinning the action a real pin. See inputs.js.
  const image = inputs.imageFor(process.env)
  const token = input('token')
  const guard = path.join(binDir, 'deter-guard')

  log(`::group::deter-guard: fetching ${image}`)
  try {
    if (token) {
      execFileSync('docker', ['login', 'ghcr.io', '-u', process.env.GITHUB_ACTOR || 'x', '--password-stdin'],
        { input: token, stdio: ['pipe', 'inherit', 'inherit'] })
    }
    run('docker', ['pull', '--quiet', image], { stdio: ['ignore', 'inherit', 'inherit'] })

    if (bool('verify-attestation')) {
      // Prove the image was built by the guard repository's own workflow rather than pushed from
      // somebody's laptop. This is the command we tell customers to run; running it here means a
      // break in it is our problem before it is theirs.
      run('gh', ['attestation', 'verify', `oci://${image}`, '--repo', GUARD_REPO],
        { stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, GH_TOKEN: token } })
    } else {
      log('::warning title=deter-guard::attestation verification is disabled')
    }

    // A scratch image has no shell, so it cannot be a job container. Lift the single static binary
    // out onto the runner, which is also the shape `serve` needs — it has to sit alongside the
    // build tooling, not in a container of its own.
    const cid = run('docker', ['create', image]).trim()
    run('docker', ['cp', `${cid}:/deter-guard`, guard])
    spawnSync('docker', ['rm', '--volumes', cid], { stdio: 'ignore' })
    fs.chmodSync(guard, 0o755)
  } catch (err) {
    fail(`could not obtain the guard from ${image}: ${err.message}`)
  }
  log('::endgroup::')

  const env = { ...process.env }
  if (consoleURL) env.DETER_CONSOLE_URL = consoleURL
  if (input('pubkey')) env.DETER_POLICY_PUBKEY = input('pubkey')
  if (input('project')) env.DETER_PROJECT = input('project')
  env.DETER_RUN_ID = input('run-id') || process.env.GITHUB_RUN_ID || ''
  env.DETER_STATE_DIR = stateDir

  const args = ['serve', '--detach', '--state-dir', stateDir]
  if (policyFile) args.push('--policy', policyFile)
  if (bool('verbose')) args.push('--verbose')

  // Transparent mode needs to write firewall rules and the system trust store, so it runs under
  // sudo. Hosted runners give passwordless sudo; a self-hosted one may not, which is why this is
  // opt-in rather than the default.
  const transparent = bool('transparent')
  if (transparent) args.push('--transparent', '--redirect', '--install-ca')
  const cmd = transparent ? 'sudo' : guard
  const argv = transparent
    // sudo drops the environment by default, and the guard needs DETER_* to reach the console.
    ? ['--preserve-env=DETER_CONSOLE_URL,DETER_POLICY_PUBKEY,DETER_PROJECT,DETER_RUN_ID,DETER_STATE_DIR,ACTIONS_ID_TOKEN_REQUEST_URL,ACTIONS_ID_TOKEN_REQUEST_TOKEN,GITHUB_ACTIONS',
       guard, ...args]
    : args

  log('::group::deter-guard: starting')
  const started = spawnSync(cmd, argv, { encoding: 'utf8', stdio: ['ignore', 'inherit', 'inherit'], env })
  log('::endgroup::')
  if (started.status !== 0) {
    fail('the guard did not start; see the log above')
  }

  // Exported even in transparent mode, and not redundantly.
  //
  // Node does NOT use the system trust store — it ships its own roots — so `--install-ca` covers
  // curl, git, python and the rest but leaves every Node tool rejecting the intercepted certificate.
  // NODE_EXTRA_CA_CERTS is what covers it. The proxy variables are belt-and-braces on top: a
  // cooperative tool takes the forward proxy (loopback, exempt from the redirect), an uncooperative
  // one gets intercepted, and both are decided by the same policy.
  //
  // Straight from the guard rather than from a list maintained here. A copy of that list in this
  // file would stop matching the guard's the next time a variable is added, and the symptom would be
  // one ecosystem quietly bypassing the proxy.
  let exported
  try {
    exported = run(guard, ['env', '--state-dir', stateDir, '--format', 'github'])
  } catch (err) {
    fail(`the guard started but did not publish its address: ${err.message}`)
  }

  if (process.env.GITHUB_ENV) fs.appendFileSync(process.env.GITHUB_ENV, exported)
  if (process.env.GITHUB_PATH) fs.appendFileSync(process.env.GITHUB_PATH, `${binDir}\n`)

  // Node's own fetch IGNORES HTTP(S)_PROXY unless asked (Node >= 24), and corepack uses it to
  // download the package manager itself. Without this the tool that fetches your dependencies is
  // the one thing that goes around the proxy — a hole in the most interesting place. Set here so
  // that no consumer has to know it exists.
  if (process.env.GITHUB_ENV) fs.appendFileSync(process.env.GITHUB_ENV, 'NODE_USE_ENV_PROXY=1\n')

  const proxy = (exported.match(/^HTTPS_PROXY=(.*)$/m) || [])[1] || 'the proxy'
  log(`deter-guard: every later step in this job now goes through ${proxy}`)
}

main()
