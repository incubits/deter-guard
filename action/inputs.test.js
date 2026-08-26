// Run with: node --test action/
//
// Node's built-in test runner, so this needs no dependencies — same rule as the rest of the action.

'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const { input, bool, imageTag, imageFor, IMAGE_REPO } = require('./inputs.js')

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

test('a pinned action ref pins the image too', () => {
  // The point of the whole release scheme. A version pin that still pulls a floating tag is not a
  // pin, and this is the action where that matters most.
  assert.equal(imageTag('v1.2.3'), '1.2.3')
  assert.equal(imageTag('v1.2'), '1.2')
  assert.equal(imageTag('v1'), '1')
  assert.equal(imageTag('1.2.3'), '1.2.3')
})

test('a commit-pinned action ref maps to the sha- tag image.yml publishes', () => {
  // metadata-action's `type=sha` is SHORT (7) by default, and lowercase.
  assert.equal(imageTag('0c9820912345678901234567890123456789abcd'), 'sha-0c98209')
  assert.equal(imageTag('0C9820912345678901234567890123456789ABCD'), 'sha-0c98209')
})

test('a branch ref maps to the branch image, sanitised the way metadata-action sanitises it', () => {
  assert.equal(imageTag('main'), 'main')
  assert.equal(imageTag('feat/egress'), 'feat-egress')
  // A leading `v` is stripped only from a version. Branches are allowed to start with one.
  assert.equal(imageTag('verbose'), 'verbose')
  assert.equal(imageTag('v-next'), 'v-next')
})

test('an unknown ref falls back to latest rather than to an unpullable name', () => {
  // `uses: ./` in this repository's own workflows sets no ref. A wrong-but-pullable tag beats a
  // confusing "manifest unknown" on the first line of somebody's build.
  assert.equal(imageTag(''), 'latest')
  assert.equal(imageTag(undefined), 'latest')
  assert.equal(imageTag('  '), 'latest')
})

test('an explicit image input wins over the derived one', () => {
  // Someone mirroring the image into their own registry has already decided.
  const env = { INPUT_IMAGE: 'registry.internal/deter-guard:1.2.3', GITHUB_ACTION_REF: 'v1' }
  assert.equal(imageFor(env), 'registry.internal/deter-guard:1.2.3')
  assert.equal(imageFor({ GITHUB_ACTION_REF: 'v1' }), `${IMAGE_REPO}:1`)
  assert.equal(imageFor({ INPUT_IMAGE: '  ', GITHUB_ACTION_REF: 'v1' }), `${IMAGE_REPO}:1`)
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
