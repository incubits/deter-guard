// What this pins is small and boring, and both failures it catches would be invisible until a
// customer's very first run of us — the worst place to find out.
//
//   1. claim.js reaches UP a directory for the two shared modules. Nothing in a normal edit-and-test
//      loop exercises that path, so moving or renaming either file breaks the action while every
//      other check stays green.
//   2. The console's wizard emits a snippet with NO `with:` block for the hosted console. That is
//      only correct while the `console` input's default is the hosted URL. If this default changes,
//      the shortest snippet we publish silently starts claiming against the wrong console.

'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const fs = require('node:fs')
const path = require('node:path')

const actionYml = fs.readFileSync(path.join(__dirname, 'action.yml'), 'utf8')

test('claim.js can resolve the modules it shares with the main action', () => {
  // require.resolve from this file resolves exactly as it does from claim.js, which sits beside it.
  assert.doesNotThrow(() => require.resolve('../action/inputs.js'))
  assert.doesNotThrow(() => require.resolve('../action/image.js'))
  assert.strictEqual(typeof require('../action/image.js').fetchGuard, 'function')
  assert.strictEqual(typeof require('../action/inputs.js').imageFor, 'function')
})

test('the entrypoint action.yml names actually exists', () => {
  const main = (actionYml.match(/^\s*main:\s*(\S+)\s*$/m) || [])[1]
  assert.ok(main, 'action.yml declares no `main:`')
  assert.ok(fs.existsSync(path.join(__dirname, main)), `main: ${main} does not exist`)
})

test('the console input defaults to the hosted console, so the snippet needs no `with:`', () => {
  assert.match(actionYml, /default:\s*https:\/\/console\.deter\.dev/,
    'the wizard publishes a snippet with no `with:` block; that is only right while this is the default')
})
