// Run with: node --test ci/semantic.test.js
//
// The rules decide whether a release is allowed to happen, which is exactly the kind of logic that
// is wrong quietly. Node's built-in runner, no dependencies, same rule as the rest of the repo.

'use strict'

const { test } = require('node:test')
const assert = require('node:assert')

const {
  parseSubject, isBreaking, requiredBump, nextVersion, compareVersions, checkVersion, checkBranch,
  MAX_SUBJECT,
} = require('./semantic.js')

test('a conventional subject comes apart into its pieces', () => {
  assert.deepEqual(parseSubject('feat: Decide on the same request you send'), {
    ok: true, type: 'feat', scope: null, breaking: false,
    description: 'Decide on the same request you send',
  })
  assert.deepEqual(parseSubject('fix(proxy)!: Reject a CONNECT with no SNI'), {
    ok: true, type: 'fix', scope: 'proxy', breaking: true,
    description: 'Reject a CONNECT with no SNI',
  })
})

test('the squash suffix GitHub appends is not held against the author', () => {
  // A title is reviewed without " (#123)" and lands with it. Measuring the version that lands would
  // make every author leave room for a number they cannot predict.
  const long = `feat: ${'A'.repeat(MAX_SUBJECT - 'feat: '.length)}`
  assert.equal(parseSubject(long).ok, true)
  assert.equal(parseSubject(`${long} (#1234)`).ok, true)
  assert.equal(parseSubject(`${long}X`).ok, false)
})

test('the house voice survives the convention', () => {
  // Conventional Commits does not require a lowercase description, and this repository writes
  // sentence-case prose. Both rules hold at once, which is the whole reason for adopting the format
  // rather than something bespoke.
  assert.equal(parseSubject('feat: Capitalised prose').ok, true)
  assert.match(parseSubject('feat: lowercase prose').reason, /capital/)
  assert.match(parseSubject('feat: Ends with a stop.').reason, /full stop/)
})

test('a subject with no type, or an invented one, is refused', () => {
  // Every commit in this repository's history before enforcement looks like the first of these.
  assert.equal(parseSubject('Decide on the same request you send').ok, false)
  assert.match(parseSubject('feature: A new thing').reason, /unknown type/)
  assert.match(parseSubject('FEAT: Shouty').reason, /expected/)
  assert.match(parseSubject('feat:No space').reason, /expected/)
  assert.match(parseSubject('').reason, /empty/)
})

test('breaking is read from the subject or from a footer', () => {
  // Somebody who writes the footer and forgets the `!` means it just as much, and the consequence
  // is identical either way.
  assert.equal(isBreaking(parseSubject('feat!: X'), ''), true)
  assert.equal(isBreaking(parseSubject('feat: X'), 'BREAKING CHANGE: the --policy flag is gone'), true)
  assert.equal(isBreaking(parseSubject('feat: X'), 'BREAKING-CHANGE: same thing, hyphenated'), true)
  assert.equal(isBreaking(parseSubject('feat: X'), 'a breaking change would be bad'), false)
})

test('the required bump is the largest across the commits', () => {
  assert.equal(requiredBump([{ subject: 'docs: A' }, { subject: 'chore: B' }]), 'none')
  assert.equal(requiredBump([{ subject: 'docs: A' }, { subject: 'fix: B' }]), 'patch')
  assert.equal(requiredBump([{ subject: 'fix: A' }, { subject: 'feat: B' }]), 'minor')
  assert.equal(requiredBump([{ subject: 'docs: A' }, { subject: 'fix!: B' }]), 'major')
  assert.equal(requiredBump([]), 'none')
})

test('an unparseable commit counts as a patch, never as a major', () => {
  // Enforcement is newer than the history, so some of it does not parse. "I cannot tell what this
  // was" should assume something shipped — but never invent a broken promise, which is the more
  // expensive mistake and is never subtle when it is real.
  assert.equal(requiredBump([{ subject: 'Rewrite in Go: 5.8 MB scratch image' }]), 'patch')
  assert.equal(requiredBump([{ subject: 'Something breaking, unlabelled' }]), 'patch')
})

test('nextVersion resets the smaller parts', () => {
  assert.equal(nextVersion('1.4.2', 'major'), '2.0.0')
  assert.equal(nextVersion('1.4.2', 'minor'), '1.5.0')
  assert.equal(nextVersion('1.4.2', 'patch'), '1.4.3')
  assert.equal(nextVersion('1.4.2', 'none'), '1.4.2')
})

test('versions compare by number, not by string', () => {
  // The bug every hand-rolled version check has: "1.10.0" < "1.9.0" lexicographically.
  assert.equal(compareVersions('1.10.0', '1.9.0'), 1)
  assert.equal(compareVersions('1.0.0', '1.0.0'), 0)
  assert.equal(compareVersions('1.0.0', '2.0.0'), -1)
})

test('a bump smaller than what has landed is refused', () => {
  // The point of the file. A minor's worth of change shipped as 1.0.1 is invisible to `@v1.0` and
  // arrives at `@v1` without the number admitting it.
  const r = checkVersion({
    version: '1.0.1', lastRelease: '1.0.0',
    commits: [{ subject: 'feat: A new input' }],
  })
  assert.equal(r.ok, false)
  assert.equal(r.minimum, '1.1.0')
  assert.match(r.reason, /too small/)
})

test('a breaking change cannot ship as a minor', () => {
  const r = checkVersion({
    version: '1.1.0', lastRelease: '1.0.0',
    commits: [{ subject: 'feat!: Rename the console input' }],
  })
  assert.equal(r.ok, false)
  assert.equal(r.minimum, '2.0.0')
})

test('a bigger bump than required is the maintainer\'s call', () => {
  // Deciding that something is a 2.0.0 is a judgement about consumers. No rule here is entitled to
  // overrule it in the other direction.
  assert.equal(checkVersion({
    version: '2.0.0', lastRelease: '1.0.0', commits: [{ subject: 'fix: A' }],
  }).ok, true)
})

test('leaving VERSION alone is always allowed, and says what it is holding', () => {
  // Releases are batched on purpose: a change may sit on main until somebody decides to cut one.
  const r = checkVersion({
    version: '1.0.0', lastRelease: '1.0.0', commits: [{ subject: 'feat: A' }],
  })
  assert.equal(r.ok, true)
  assert.equal(r.released, false)
  assert.equal(r.minimum, '1.1.0')
})

test('VERSION cannot go backwards, and must be a version at all', () => {
  assert.match(checkVersion({ version: '0.9.0', lastRelease: '1.0.0', commits: [] }).reason, /older/)
  assert.match(checkVersion({ version: '1.2', lastRelease: '1.0.0', commits: [] }).reason, /MAJOR\.MINOR\.PATCH/)
})

test('before the first release there is no floor', () => {
  assert.equal(checkVersion({
    version: '1.0.0', lastRelease: null, commits: [{ subject: 'feat!: Anything' }],
  }).ok, true)
})

test('a branch declares the same type its commits do', () => {
  assert.equal(checkBranch('feat/transparent-mode').type, 'feat')
  assert.equal(checkBranch('ci/semantic-conventions').ok, true)
  assert.equal(checkBranch('fix/egress/host-header').ok, true)
  assert.match(checkBranch('transparent-mode').reason, /type\/short-slug/)
  assert.match(checkBranch('feature/x').reason, /unknown type/)
  assert.match(checkBranch('feat/Transparent_Mode').reason, /type\/short-slug/)
})

test('branches nobody chose the name of are exempt', () => {
  // Failing a revert because the revert button named the branch would be a rule getting in the way
  // at the one moment somebody is in a hurry.
  for (const b of ['main', 'dependabot/github_actions/actions/checkout-5', 'revert-7-feat/x']) {
    assert.equal(checkBranch(b).ok, true, `${b} should be exempt`)
  }
})
