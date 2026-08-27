// Enforces ci/semantic.js against a pull request or a push. Run by the Conventions job in
// .github/workflows/image.yml; the rules in prose are in CONTRIBUTING.md.
//
//   node ci/check.js
//
// Everything it needs arrives through the environment. A pull request title is attacker-controlled
// text on a public repository, so it reaches this program as an environment variable and, at worst,
// as an argument to execFileSync — never as part of a string a shell parses.

'use strict'

const { execFileSync } = require('node:child_process')
const fs = require('node:fs')

const s = require('./semantic.js')

// ASCII record and unit separators. A commit body holds anything a person can type — newlines and
// blank lines very much included — so the delimiters have to be bytes git will not emit itself.
const RECORD = '\x1e'
const UNIT = '\x1f'

let failed = false

/**
 * An annotation as well as a non-zero exit, so the reason lands on the run summary rather than only
 * in a step log somebody has to expand. `%0A` is how a multi-line annotation is spelled.
 *
 * The title is a fixed string chosen by this file, never the subject being complained about: an
 * annotation is a `::`-delimited format, and the text under discussion is written by whoever opened
 * the pull request.
 */
function fail(title, message) {
  process.stdout.write(`::error title=${title}::${message.replace(/\n/g, '%0A')}\n`)
  failed = true
}

function note(message) {
  process.stdout.write(`${message}\n`)
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${message}\n`)
  }
}

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim()
}

/** The commits in `range`, merges excluded — a merge subject is written by git, not by a person. */
function commitsIn(range) {
  const out = execFileSync('git', ['log', '--no-merges', `--format=%s${UNIT}%b${RECORD}`, range], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  return out
    .split(RECORD)
    .map((chunk) => chunk.replace(/^\s+/, ''))
    .filter((chunk) => chunk.trim())
    .map((chunk) => {
      const cut = chunk.indexOf(UNIT)
      return {
        subject: (cut === -1 ? chunk : chunk.slice(0, cut)).trim(),
        body: (cut === -1 ? '' : chunk.slice(cut + 1)).trim(),
      }
    })
}

/**
 * The newest release tag reachable from HEAD, without its `v`, or null before the first release.
 *
 * The glob needs both dots, so it selects v1.2.3 and skips the moving v1 and v1.2 that point at the
 * same commit.
 */
function lastRelease() {
  try {
    return git('describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*.[0-9]*.[0-9]*').replace(/^v/, '')
  } catch {
    return null
  }
}

function checkSubject(what, subject, body) {
  const parsed = s.parseSubject(subject)
  if (!parsed.ok) {
    fail(what, `${JSON.stringify(subject)}\n${parsed.reason}\n\n` +
               'See CONTRIBUTING.md. Example: fix(proxy): Reject a CONNECT with no SNI')
    return
  }
  if (s.isBreaking(parsed, body)) {
    // Said out loud rather than only folded into the floor, because it is the one classification a
    // reviewer should disagree with before it is merged, not after.
    note(`Breaking change declared — the next release can only be a major.`)
  }
}

function main() {
  const isPR = (process.env.EVENT || '') === 'pull_request'

  if (isPR) {
    // The branch. On a push to main there is nothing to check: `main` is exempt, and the branch it
    // came from no longer exists by then.
    const b = s.checkBranch(process.env.BRANCH || '')
    if (!b.ok) {
      fail('Branch name', `${b.reason}\n\nSee CONTRIBUTING.md. Example: feat/transparent-mode`)
    }

    // The pull request TITLE matters most: this repository squashes, so the title is the subject
    // that lands on main and is read forever after. The commits behind it are checked too, but
    // they are the draft and this is what gets published.
    checkSubject('Pull request title', process.env.PR_TITLE || '', process.env.PR_BODY || '')

    const base = process.env.BASE_SHA
    const head = process.env.HEAD_SHA
    if (base && head) {
      const commits = commitsIn(`${base}..${head}`)
      for (const commit of commits) checkSubject('Commit', commit.subject, commit.body)
      note(`Checked the branch name, the title, and ${commits.length} commit(s).`)
    }
  } else {
    // A push. On main this is the squashed subject already checked as a pull request title, but a
    // direct push skips that, and this is where it gets caught.
    const subject = git('log', '-1', '--no-merges', '--format=%s')
    if (subject) checkSubject('Commit', subject, git('log', '-1', '--no-merges', '--format=%b'))
  }

  // The version floor. Everything unreleased is in scope, not only this branch: the question is not
  // "is this pull request a feature" but "is the number about to be published big enough for
  // everything it will carry" — and a feature merged last week counts just as much.
  const version = fs.readFileSync('VERSION', 'utf8').trim()
  const last = lastRelease()

  // Specifically, what main will look like once this lands. On a pull request that is the commits
  // already on main since the last tag, plus exactly ONE for this pull request: the merge squashes,
  // so the title is the only subject of it that will survive. Reading the branch's own draft commits
  // here instead would both miss a `!` that appears only in the title, and let a stray work-in-
  // progress `feat:` raise the floor for something that ships as a `fix:`.
  const base = isPR ? process.env.BASE_SHA : null
  const onMain = commitsIn(last ? `v${last}..${base || 'HEAD'}` : base || 'HEAD')
  const unreleased = isPR
    ? [...onMain, { subject: process.env.PR_TITLE || '', body: process.env.PR_BODY || '' }]
    : onMain

  const result = s.checkVersion({ version, lastRelease: last, commits: unreleased })

  if (!result.ok) {
    fail('VERSION', `${result.reason}\n\nSee CONTRIBUTING.md.`)
  } else if (result.released) {
    const floor = result.bump === 'none'
      ? 'nothing unreleased required one'
      : `the ${unreleased.length} unreleased commit(s) require a \`${result.bump}\``
    note(`Releasing **v${version}** — ${floor}.`)
  } else if (result.bump === 'none') {
    note(`No release: VERSION is still \`${version}\`, and nothing unreleased needs one.`)
  } else {
    note(`No release yet: ${unreleased.length} unreleased commit(s) require a \`${result.bump}\`. ` +
         `Set \`VERSION\` to at least \`${result.minimum}\` to ship them.`)
  }

  process.exit(failed ? 1 : 0)
}

main()
