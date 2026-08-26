// Reading action inputs off the environment.
//
// Its own module purely so it can be tested. The bug that caused it to exist was silent in the worst
// possible way: `verify-attestation` read as unset, so the action skipped the provenance check it
// exists to perform, and still reported success. It was caught only because that particular branch
// happens to log a warning.

'use strict'

/**
 * GitHub maps an input id to an environment variable by uppercasing it and replacing SPACES with
 * underscores. Hyphens are left ALONE:
 *
 *   verify-attestation  ->  INPUT_VERIFY-ATTESTATION     (not INPUT_VERIFY_ATTESTATION)
 *   some input          ->  INPUT_SOME_INPUT
 *
 * This matches @actions/core's getInput. Replacing hyphens as well — the intuitive thing to write,
 * and what this did originally — makes every hyphenated input read as empty.
 */
function input(env, name) {
  return (env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '').trim()
}

/**
 * Booleans arrive as strings, and "not set" must not be confused with "false" by accident even
 * though they behave the same: anything unrecognised is false, so a caller has to say so to get true.
 */
function bool(env, name) {
  return /^(true|1|yes)$/i.test(input(env, name))
}

/** Where the guard image lives: same repository as this action, published by image.yml. */
const IMAGE_REPO = 'ghcr.io/incubits/deter-guard'

/**
 * The image tag corresponding to a given ref of this action.
 *
 * The action and the image are cut from the same commit by the same workflow, so the default is to
 * pull the image matching the ref the caller pinned rather than a floating `:latest`. Otherwise
 * `uses: incubits/deter-guard@v1.2.3` would still run whatever `:latest` happened to be that
 * morning — not a pin, only the look of one, and this is the one action where that distinction is
 * the entire product.
 *
 *   v1.2.3           ->  1.2.3
 *   v1               ->  1              (the moving major tag, on both sides)
 *   main             ->  main           (image.yml tags every branch build)
 *   feat/x           ->  feat-x         (`/` is not legal in an image tag)
 *   <40-hex commit>  ->  sha-<7>        (image.yml's `type=sha,prefix=sha-`, short by default)
 *   ''               ->  latest         (unset: a local `uses: ./`, or a runner that omits it)
 */
function imageTag(ref) {
  const r = (ref || '').trim()
  if (!r) return 'latest'
  if (/^[0-9a-f]{40}$/i.test(r)) return `sha-${r.slice(0, 7).toLowerCase()}`
  // Strip a leading `v` only from something already shaped like a version: a branch called
  // `verbose` is not v1.
  const v = r.replace(/^v(?=\d)/, '')
  if (/^\d+(\.\d+){0,2}$/.test(v)) return v
  // A branch name. docker/metadata-action replaces whatever is not legal in a tag with `-`.
  return r.replace(/[^A-Za-z0-9._-]/g, '-')
}

/**
 * The image to take the binary from: the `image` input when the caller set one, otherwise the image
 * matching this action's own ref. An explicit value is used verbatim — someone mirroring the image
 * into their own registry has already decided.
 */
function imageFor(env) {
  return input(env, 'image') || `${IMAGE_REPO}:${imageTag(env.GITHUB_ACTION_REF)}`
}

module.exports = { input, bool, imageTag, imageFor, IMAGE_REPO }
