// Run with: node --test action/
//
// Node's built-in test runner, so this needs no dependencies — same rule as the rest of the action.

'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const { input, bool } = require('./inputs.js')

test('a hyphenated input keeps its hyphen in the env var name', () => {
  // The regression. GitHub sets INPUT_VERIFY-ATTESTATION; reading INPUT_VERIFY_ATTESTATION finds
  // nothing, so the input reads as unset and the provenance check is skipped while the run still
  // goes green. Security controls must not be disabled by a typo in a variable name.
  const env = { 'INPUT_VERIFY-ATTESTATION': 'true' }
  assert.equal(input(env, 'verify-attestation'), 'true')
  assert.equal(bool(env, 'verify-attestation'), true)
})

test('every hyphenated input this action declares is readable', () => {
  // Guards the whole surface rather than the one input that happened to be caught.
  const declared = ['verify-attestation', 'run-id']
  for (const name of declared) {
    const key = `INPUT_${name.replace(/ /g, '_').toUpperCase()}`
    assert.equal(input({ [key]: 'x' }, name), 'x', `${name} is not readable`)
    assert.ok(key.includes('-'), `${key} should still contain a hyphen`)
  }
})

test('a space becomes an underscore, unlike a hyphen', () => {
  assert.equal(input({ INPUT_SOME_INPUT: 'v' }, 'some input'), 'v')
})

test('an unset input is empty, not undefined', () => {
  // Callers do `.trim()`-ed string comparisons and `push(...)` these into argv; undefined would
  // become the literal string "undefined" somewhere unpleasant.
  assert.equal(input({}, 'console'), '')
  assert.equal(bool({}, 'transparent'), false)
})

test('surrounding whitespace is stripped', () => {
  // YAML block scalars love trailing newlines, and a console URL with one appended fails in a way
  // that looks like the console is down.
  assert.equal(input({ INPUT_CONSOLE: '  https://x.example  \n' }, 'console'), 'https://x.example')
})

test('only affirmative spellings are true', () => {
  for (const v of ['true', 'TRUE', 'True', '1', 'yes', 'YES']) {
    assert.equal(bool({ INPUT_T: v }, 't'), true, `${v} should be true`)
  }
  // "false" and anything unrecognised are false. Notably an empty string, so a declared-but-unset
  // boolean never turns a feature on.
  for (const v of ['false', 'FALSE', '0', 'no', '', 'maybe', 'null']) {
    assert.equal(bool({ INPUT_T: v }, 't'), false, `${v} should be false`)
  }
})
