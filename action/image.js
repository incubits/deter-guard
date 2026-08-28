// Getting the guard binary onto the runner: pull the image, prove where it came from, lift the
// static binary out.
//
// Shared by the two actions rather than copied into each. It was copied, briefly, and the copies
// immediately disagreed about whether a failed `docker login` should end the job — which is exactly
// the kind of difference nobody notices until it is a customer's first five minutes.

'use strict'

const { execFileSync, spawnSync } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const GUARD_REPO = 'incubits/deter-guard'

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...opts })
}

/**
 * Returns the path to a ready-to-run guard binary.
 *
 * Throws if the image cannot be obtained or its provenance cannot be established — both are
 * failures the caller should turn into a red job, because a guard of unknown origin is worse than
 * no guard.
 */
function fetchGuard({ image, token, verifyAttestation, binDir, log }) {
  fs.mkdirSync(binDir, { recursive: true })
  const guard = path.join(binDir, 'deter-guard')

  log(`::group::deter-guard: fetching ${image}`)

  if (token) {
    // Deliberately not fatal. The published image is PUBLIC, so the pull below needs no credential
    // at all; a login only matters for someone who pointed `image` at a private mirror. Meanwhile a
    // job that declares `permissions: id-token: write` and nothing else gets a GITHUB_TOKEN with no
    // packages scope — and making that fatal would break the one workflow we ask every new customer
    // to paste, for a credential the normal path never needed.
    try {
      execFileSync('docker', ['login', 'ghcr.io', '-u', process.env.GITHUB_ACTOR || 'x', '--password-stdin'],
        { input: token, stdio: ['pipe', 'ignore', 'inherit'] })
    } catch {
      log('::debug::could not log in to ghcr.io; continuing anonymously, which is enough for the published image')
    }
  }

  run('docker', ['pull', '--quiet', image], { stdio: ['ignore', 'inherit', 'inherit'] })

  if (verifyAttestation) {
    // Prove the image was built by the guard repository's own workflow rather than pushed from
    // somebody's laptop. This is the command we tell customers to run; running it here means a
    // break in it is our problem before it is theirs.
    run('gh', ['attestation', 'verify', `oci://${image}`, '--repo', GUARD_REPO],
      { stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, GH_TOKEN: token } })
  } else {
    log('::warning title=deter-guard::attestation verification is disabled')
  }

  // The image carries a shell now, but the binary still comes OUT of it rather than the job running
  // inside it: `serve` has to sit alongside the build tooling it is filtering, not in a container of
  // its own, and `claim` may as well take the same path.
  const cid = run('docker', ['create', image]).trim()
  run('docker', ['cp', `${cid}:/deter-guard`, guard])
  spawnSync('docker', ['rm', '--volumes', cid], { stdio: 'ignore' })
  fs.chmodSync(guard, 0o755)

  log('::endgroup::')
  return guard
}

module.exports = { fetchGuard, run, GUARD_REPO }
