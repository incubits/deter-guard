# Contributing

Branches and commits are named so that a machine can tell what kind of change they are. That is not
tidiness. `VERSION` is a number a person chooses, and these names are what CI checks that number
against: a feature that has landed since the last release means the next release cannot be a patch,
and a breaking change means it can only be a major.

Nothing here ever picks the version for you. It only refuses one that would quietly break everyone
pinned to `@v1`.

## Commit subjects

[Conventional Commits](https://www.conventionalcommits.org), with the description left as prose:

```
feat(proxy)!: Decide on the same request you send
^^^^ ^^^^^ ^  ^
type scope |  description
           breaking
```

- **type** — from the table below. Required.
- **scope** — optional, lowercase, whatever names the area: `proxy`, `action`, `policy`.
- **`!`** — this change breaks something a consumer depends on. See [Breaking changes](#breaking-changes).
- **description** — a capitalised sentence, no full stop, imperative. The whole subject is at most
  72 characters, not counting the ` (#123)` GitHub appends when it squashes.

The spec does not require a lowercase description, so the house voice survives. Write the sentence
you would have written anyway; put the type in front of it.

```
feat: Filter traffic that was never told about a proxy
fix(policy): Reject a non-canonical path before the blocklist sees it
docs: Restructure the README around getting started
ci: Release on merge
```

### Types

| Type | Smallest release it may ship in | |
| --- | --- | --- |
| `feat` | **minor** | A new capability. |
| `fix` | patch | |
| `perf` | patch | |
| `refactor` | patch | The binary changes even when behaviour does not. |
| `revert` | patch | Undoing something that shipped is itself a change. |
| `build` | patch | The Dockerfile, the build — it alters the image. |
| `docs` | none | The README is not in the image. |
| `test` | none | |
| `ci` | none | |
| `chore` | none | |

"Smallest release it may ship in" is a floor, not a quota. A documentation-only change may be
released as a patch if you want it out; a `fix` may go out as part of a minor. What cannot happen is
a `feat` shipping as a patch.

## Branch names

`type/short-slug`, using the same types:

```
feat/transparent-mode
fix/host-header
ci/semantic-conventions
docs/getting-started
```

Lowercase, digits, `-`, `.` and `/`. `main` is exempt, as are the branches GitHub names for you
(`dependabot/…`, `revert-7-…`) — a rule should not get in the way at the one moment you are reverting
something in a hurry.

## Pull requests

This repository squashes, so **the pull request title is the commit that lands on main** and is read
forever after. It has to satisfy the same rules, and it is the one CI complains loudest about. The
commits behind it are checked too, but they are the draft; the title is what gets published.

Every pull request's checks summary says which of two things it is:

> No release yet: 3 unreleased commit(s) require a `minor`. Set `VERSION` to at least `1.1.0` to ship them.

> Releasing **v1.1.0** — 4 unreleased commit(s), requiring a `minor`.

## Breaking changes

Mark them with `!` after the type, or with a `BREAKING CHANGE:` footer in the body — both are read,
and both force a major.

```
feat(action)!: Rename the `console` input to `console-url`

BREAKING CHANGE: workflows setting `console:` must be updated. The old name is
not accepted, because silently ignoring it would guard nothing while looking
like it worked.
```

A breaking change is anything that changes a surface somebody has written down: an action input, a
CLI flag, an environment variable, an exit code, the policy format. Making the guard refuse
something it used to allow is *not* breaking — that is the product working.

## Cutting a release

Edit `VERSION` — one line, `MAJOR.MINOR.PATCH` — in the pull request that earns the bump:

```
1.1.0
```

Merging it publishes the image tags, moves `v1` and `v1.1`, and cuts a GitHub release. A merge that
leaves `VERSION` alone releases nothing and waits for the next one; releases are batched on purpose.

CI checks the number against **everything unreleased**, not just your branch. If somebody merged a
`feat` last week and you bump the patch, it fails — the feature would arrive at `@v1` without the
version admitting it, and `@v1.0` would never see it at all.

Deciding the number is still yours. `1.4.2` → `2.0.0` is a promise being broken for everyone pinned
to `@v1`, and no regex over a subject line is entitled to make that call.

## Checks

What CI runs, and what you can run first:

```bash
gofmt -l .                          # must print nothing
go vet ./...
go test ./...
node --test action/inputs.test.js   # the action is JavaScript; `go test` never sees it
node --test ci/semantic.test.js     # the naming and version rules
node ci/check.js                    # this file, enforced, against your checkout
```

The rules themselves live in [`ci/semantic.js`](ci/semantic.js) as tested functions rather than only
as the prose above — anything that decides whether a release may happen is worth being able to test.
