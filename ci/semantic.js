// The branch and commit naming rules, as code.
//
// They exist to serve one thing: `VERSION` is a number a person chooses, and this is what checks
// that the number is big enough. A `feat:` that has landed since the last release means the next
// release cannot be a patch. A `!` means it cannot be anything but a major. Nothing here ever picks
// the version — see .github/workflows/image.yml for why that stays a reviewed edit — it only
// refuses a bump that would quietly break everyone pinned to `@v1`.
//
// Pure functions, no I/O, so the rules can be tested rather than discovered in a red pull request.
// ci/check.js is the part that talks to git and to GitHub. Node built-ins only, same rule as the
// rest of this repository.

'use strict'

/**
 * The allowed commit types, and the SMALLEST release each one may ship in.
 *
 * The split is "does this change the artifact somebody pulls":
 *
 *   feat                  a new capability          -> at least a minor
 *   fix perf refactor     the binary changes        -> at least a patch
 *   revert build          ditto: reverts undo shipped behaviour, build changes the image
 *   docs test ci chore    nothing ships             -> no release needed at all
 *
 * `docs` is `none` because the README is not in the image. A documentation-only change may still be
 * released — this is a floor, not a quota.
 */
const TYPES = {
  feat: 'minor',
  fix: 'patch',
  perf: 'patch',
  refactor: 'patch',
  revert: 'patch',
  build: 'patch',
  docs: 'none',
  test: 'none',
  ci: 'none',
  chore: 'none',
}

/** Smallest to largest. `ORDER.indexOf` is the comparison. */
const ORDER = ['none', 'patch', 'minor', 'major']

/**
 * Conventional Commits, with the description left as prose.
 *
 *   feat(proxy)!: Decide on the same request you send
 *   ^^^^ ^^^^^  ^  ^
 *   type scope  |  description
 *               breaking
 *
 * The spec does not say the description must be lowercase, so this repository's sentence-case voice
 * survives contact with the convention. Everything else is standard, which matters because it means
 * ordinary tooling can read this history.
 */
const SUBJECT = /^([a-z]+)(?:\(([^()]+)\))?(!)?: (.+)$/

/**
 * GitHub appends ` (#123)` to the subject when it squashes a pull request, so the subject that
 * lands on main is longer than the one that was reviewed. Measure and punctuate the part a person
 * actually wrote, or every title would have to leave room for a number it cannot predict.
 */
const SQUASH_SUFFIX = / \(#\d+\)$/

/** Long enough for a real sentence, short enough for `git log --oneline` and the GitHub UI. */
const MAX_SUBJECT = 72

/**
 * Take a commit subject apart, or explain what is wrong with it.
 *
 * Returns `{ ok: true, type, scope, breaking, description }`, or `{ ok: false, reason }` where the
 * reason is written to be pasted into an annotation and acted on without opening this file.
 */
function parseSubject(subject) {
  const line = String(subject || '').trim()
  if (!line) return { ok: false, reason: 'the subject is empty' }

  const bare = line.replace(SQUASH_SUFFIX, '')
  const m = SUBJECT.exec(bare)
  if (!m) {
    return {
      ok: false,
      reason: `expected "type: Description" or "type(scope)!: Description", got ${JSON.stringify(bare)}`,
    }
  }

  const [, type, scope, bang, description] = m
  if (!Object.prototype.hasOwnProperty.call(TYPES, type)) {
    return { ok: false, reason: `unknown type ${JSON.stringify(type)} — use one of ${Object.keys(TYPES).join(', ')}` }
  }
  if (bare.length > MAX_SUBJECT) {
    return { ok: false, reason: `${bare.length} characters, at most ${MAX_SUBJECT} (the trailing " (#123)" GitHub adds is not counted)` }
  }
  if (!/^[A-Z0-9`"']/.test(description)) {
    return { ok: false, reason: `the description should start with a capital: ${JSON.stringify(description)}` }
  }
  if (description.endsWith('.')) {
    return { ok: false, reason: 'the description should not end with a full stop' }
  }

  return { ok: true, type, scope: scope || null, breaking: Boolean(bang), description }
}

/**
 * `!` in the subject is the whole story most of the time, but the spec also allows a `BREAKING
 * CHANGE:` footer in the body, and somebody who writes one and forgets the `!` means it just as
 * much. Read both; the consequence — a forced major — is the same either way.
 */
function isBreaking(parsed, body) {
  if (parsed.ok && parsed.breaking) return true
  return /^BREAKING[ -]CHANGE:/m.test(String(body || ''))
}

/** The larger of two bump levels. */
function maxBump(a, b) {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b
}

/**
 * The smallest release the given commits may ship in.
 *
 * A commit whose subject does not parse counts as a patch rather than as nothing: enforcement is
 * new, so some history predates it, and the safe reading of "I cannot tell what this was" is that
 * something shipped. It is never treated as a major — guessing a promise was broken would be worse
 * than the opposite mistake, and the `!` that means it is not subtle.
 */
function requiredBump(commits) {
  let bump = 'none'
  for (const commit of commits) {
    const parsed = parseSubject(commit.subject)
    if (isBreaking(parsed, commit.body)) return 'major'
    bump = maxBump(bump, parsed.ok ? TYPES[parsed.type] : 'patch')
  }
  return bump
}

function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v || '').trim())
  if (!m) return null
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) }
}

/** -1, 0 or 1. Throws on anything that is not MAJOR.MINOR.PATCH, which VERSION is checked to be. */
function compareVersions(a, b) {
  const x = parseVersion(a)
  const y = parseVersion(b)
  if (!x || !y) throw new TypeError(`not a version: ${JSON.stringify(!x ? a : b)}`)
  for (const part of ['major', 'minor', 'patch']) {
    if (x[part] !== y[part]) return x[part] < y[part] ? -1 : 1
  }
  return 0
}

/** The smallest version that counts as `bump` applied to `from`. */
function nextVersion(from, bump) {
  const v = parseVersion(from)
  if (!v) throw new TypeError(`not a version: ${JSON.stringify(from)}`)
  if (bump === 'major') return `${v.major + 1}.0.0`
  if (bump === 'minor') return `${v.major}.${v.minor + 1}.0`
  if (bump === 'patch') return `${v.major}.${v.minor}.${v.patch + 1}`
  return `${v.major}.${v.minor}.${v.patch}`
}

/**
 * Is this VERSION acceptable, given what has landed since `lastRelease`?
 *
 * Three outcomes, and the middle one is the point of the whole file:
 *
 *   unchanged   nothing is released by this push. Always allowed — releases are batched on purpose,
 *               and a change may sit on main until somebody decides to cut one.
 *   too small   REFUSED. A minor's worth of change cannot ship as 1.0.1, because `@v1.0` would
 *               never see it and `@v1` would get it without the version saying so.
 *   big enough  allowed, including bigger than required. Choosing to call something 2.0.0 is a
 *               judgement about consumers that no rule here is entitled to overrule.
 */
function checkVersion({ version, lastRelease, commits }) {
  const bump = requiredBump(commits)

  if (!parseVersion(version)) {
    return { ok: false, bump, reason: `VERSION must be MAJOR.MINOR.PATCH, got ${JSON.stringify(version)}` }
  }
  if (!lastRelease) {
    // Nothing has been released yet, so there is no floor to be under.
    return { ok: true, bump, released: true, minimum: version }
  }

  const cmp = compareVersions(version, lastRelease)
  if (cmp === 0) return { ok: true, bump, released: false, minimum: nextVersion(lastRelease, bump) }
  if (cmp < 0) {
    return { ok: false, bump, reason: `VERSION ${version} is older than the last release ${lastRelease}` }
  }

  const minimum = nextVersion(lastRelease, bump)
  if (compareVersions(version, minimum) < 0) {
    return {
      ok: false,
      bump,
      minimum,
      reason: `VERSION ${version} is too small: a ${bump} has landed since ${lastRelease}, so the next release is at least ${minimum}`,
    }
  }
  return { ok: true, bump, released: true, minimum }
}

/**
 * Branch names carry the same type, so what a branch is for is legible before anything is merged —
 * and so the reviewer of a `feat/` branch knows to look at VERSION before approving it.
 *
 *   feat/transparent-mode        ci/semantic-conventions        fix/host-header
 */
const BRANCH = /^([a-z]+)\/[a-z0-9]+(?:[-./][a-z0-9]+)*$/

/**
 * Branches nobody chose the name of. `main` is the trunk; the other two are named by GitHub itself
 * when you press a button, and failing a revert because the revert button named the branch would be
 * a rule getting in the way of the one moment somebody is in a hurry.
 */
const EXEMPT_BRANCHES = [/^main$/, /^dependabot\//, /^revert-\d+-/]

function checkBranch(name) {
  const branch = String(name || '').trim()
  if (!branch) return { ok: false, reason: 'the branch name is empty' }
  if (EXEMPT_BRANCHES.some((re) => re.test(branch))) return { ok: true, exempt: true }

  const m = BRANCH.exec(branch)
  if (!m) {
    return { ok: false, reason: `expected "type/short-slug", got ${JSON.stringify(branch)}` }
  }
  if (!Object.prototype.hasOwnProperty.call(TYPES, m[1])) {
    return { ok: false, reason: `unknown type ${JSON.stringify(m[1])} — use one of ${Object.keys(TYPES).join(', ')}` }
  }
  return { ok: true, type: m[1] }
}

module.exports = {
  TYPES,
  ORDER,
  MAX_SUBJECT,
  parseSubject,
  isBreaking,
  maxBump,
  requiredBump,
  parseVersion,
  compareVersions,
  nextVersion,
  checkVersion,
  checkBranch,
}
