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

module.exports = { input, bool }
