# What this fork changes, and why it is not upstream

This branch (`develop`) is upstream's `main` plus the patches below. Anything
generally useful is offered upstream first; what remains here is listed with
the reason it stays.

Keep this file current — it is what tells you, months later, which divergence
was deliberate.

## Branches

| branch | meaning |
|---|---|
| `main` | a mirror of upstream. Fast-forward only, never commit to it. |
| `develop` | the product: upstream plus the patches below. |
| `feature/<name>` | new work, cut from `main` so it can become a PR unchanged. |

Releases are tags on `develop`. Rebasing `develop` during a sync never
disturbs them.

## Syncing with upstream

```sh
git fetch upstream
git checkout main && git merge --ff-only upstream/main && git push origin main
git rebase -i upstream/main develop
```

Drop any commit upstream has already taken — GitHub squash-merges, so your
originals do not disappear by themselves and will conflict. Identify them by
content, not by subject:

```sh
git grep -c '<a symbol the commit introduced>' upstream/main -- '*.go'
```

Then `go build ./...` and `go test ./...` in `server-go` and `agent`,
`npm run lint` in `app`, and deploy before tagging.

## What is here, and where it should end up

Nothing in this fork has been offered upstream yet. Grouped for review, largest
coherent feature first:

| area | commits | offer upstream? |
|---|---|---|
| UniFi controller integration | 13 | yes — generic |
| Proxmox integration | 7 | yes — generic |
| Routers / topology / devices | 11 | yes, mostly bug fixes |
| WAN, alerts, VLANs, agents | ~8 | yes |
| UI, i18n, comments | ~12 | yes, where not cosmetic |

Check each against `upstream/main` first: upstream moves quickly (2.28.x) and
some of these may already be solved there.

## Fork-only patches

| patch | why it is not upstream |
|---|---|
| — | none yet. Everything here is upstreamable and simply has not been offered. |

## Running this fork as the product

The update channel is configuration, not code: upstream already reads
`GITHUB_REPO` (`server-go/internal/config/config.go:356`, also exposed via UCI
as `github_repo`). Point a deployment at this fork's releases with

```
GITHUB_REPO=borky/netpulse
```

in its `.env`. Nothing in the source needs to change, which is why there is no
fork patch for it.

## The identifying-data hooks

`.git/hooks/pre-commit` scans the staged diff and `.git/hooks/commit-msg`
scans the message, both against the patterns in
`~/.claude/no-identifying-data.txt`. A match blocks the commit and names the
pattern that fired.

This repository needed them: the agent fixtures carried the router model in
their identifiers and comments long after the addresses in them had been
replaced with documentation ranges. Scrubbing that out of 51 commits required
rewriting the branch.

Hooks are not versioned, so **a fresh clone has no protection until they are
reinstalled**. Copy the four files into the new clone's `.git/hooks/` and
mark them executable.

## The AI-trailer hook

`.git/hooks/no-ai-trailers.py`, also run from `commit-msg`, refuses a message
carrying `Co-Authored-By` for an AI tool, a "generated with" footer or the
robot emoji. The maintainer asked for this on the panel's repo — "this repo
keeps AI tooling out of the recorded history" — and enforced it there by
force-pushing `main` to strip such trailers from an already-merged branch,
which changed every commit hash after it and broke every open PR based on the
old history. Same maintainer here, so the same rule is assumed.

It needs no pattern file, so it works as soon as the hooks are copied in. A
human co-author still passes. **`git rebase` and `git filter-branch` do not run
`commit-msg`**, so a replay of older commits can still carry one through; to
clean a branch:

```sh
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f \
  --msg-filter 'sed "/^Co-Authored-By: Claude/d"' upstream/main..HEAD
```

## The agent module

`agent/` is its own Go module (`github.com/gnacho/netpulse/agent`) and the
router panel depends on it. Two payload fields it gained here — the panel's
port and the uplink policy — are what the panel's own fork needs, and they are
not in a released agent yet, so that side builds with a Go workspace.

**Do not rename the module path** in this fork: every internal import would
change, guaranteeing conflicts on every sync. The fix is to get those fields
upstream and released; upstream's `feat(agent): decouple agent version from
server release tag (#791)` makes that easier.
