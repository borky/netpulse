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
# Read what the new commits send out of the network BEFORE anything moves -
# see "Outbound check" below. Once main is fast-forwarded there is nothing
# left to compare.
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
`npm run lint` in `app`, and deploy before tagging. `go test` is also where a
call home brought back by a sync shows up - see the fork-only patches below.

### Outbound check

This fork sends no identifying data anywhere, and upstream has added outbound
calls before without it being obvious from the subject line. Run this right
after `git fetch upstream`, before the fast-forward:

```sh
base=$(git merge-base origin/develop upstream/main)   # the develop you last pushed
pat='[a-z][a-z0-9+.-]*://[a-zA-Z0-9.%/_?=&:-]+'   # any scheme: MQTT is tcp://
git grep -hoE "$pat" "$base"       -- '*.go' '*.ts' '*.tsx' ':!*_test.go' ':!*.test.ts' ':!*.test.tsx' | sort -u > /tmp/np-before
git grep -hoE "$pat" upstream/main -- '*.go' '*.ts' '*.tsx' ':!*_test.go' ':!*.test.ts' ':!*.test.tsx' | sort -u > /tmp/np-after
diff /tmp/np-before /tmp/np-after
```

It compares against the base of the `develop` you last pushed, which does
not move until you push again, so it still gives the right answer partway
through a sync - after the fast-forward, even after the rebase. Once the new
`develop` is pushed there is nothing left to compare, so run it before then.
It covers the server, the
agent (which runs on routers inside NetGrip) and the web app. Any new
endpoint gets read before it is merged: what it sends, whether it is on by
default, and whether it carries anything that identifies the installation.
A URL assembled at runtime from pieces will not show up here; the guard tests
below are the second line for the project's own domain.

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
| HTTPS with a private CA (see below) | ~12 | yes — opt-in, defaults unchanged |

Check each against `upstream/main` first: upstream moves quickly (2.28.x) and
some of these may already be solved there.

## Fork-only patches

| patch | why it is not upstream |
|---|---|
| **Instance telemetry never wired** — `server-go/cmd/netpulse/main.go` does not import `internal/telemetry` | This fork sends no identifying data anywhere. Upstream's ping (#822) is on by default and carries a persistent instance id. See below. |

### Why telemetry is unwired, not deleted

Upstream's anonymous daily ping (#822) sends `GET /instances/<id>?v=<version>&os=<os-arch>`
to the project's server, once a day, on by default. The id is random but
**persistent** — it ties one installation together across every ping for as
long as it runs — and like any request it discloses the server's public
address. That is identifying data leaving the network, which this fork does
not do.

There were three ways to keep it out, and only one keeps syncs cheap:

| approach | telemetry in the binary? | cost at every sync |
|---|---|---|
| set `NETPULSE_TELEMETRY=0` at deploy | yes, switched off at runtime | none — but it is one missed environment variable from sending |
| delete `internal/telemetry/` | no | a modify/delete conflict every time upstream touches the package |
| **remove only the wiring in `main.go`** | **no — unreferenced, it is never linked** | only if upstream edits those exact lines |

The package's source stays in the tree, untouched, so upstream's changes to
it merge silently. What runs on the server is a binary with no
telemetry code in it at all, rather than one with code that is switched off.

**The guards.** Three new, fork-only test files:

- `server-go/cmd/netpulse/no_telemetry_test.go` reads every non-test `.go`
  file in `server-go` and fails on an import of the telemetry package outside
  itself, on any reference to `NETPULSE_TELEMETRY`, and on **any** mention of
  the project's domain, `cloudless.club`, other than the announcements feed.
  The last rule also catches the ping rebuilt without the package, a new host,
  and a host name split across strings. The allowed feed is matched as a whole
  quoted literal, so nothing can be tacked onto it in the source.
- `server-go/internal/httpapi/no_call_home_announcements_test.go` covers what
  a source scan cannot: something built onto the feed's request in code. It
  drives the real start path against a local server and fails unless the
  request is a plain GET of the static file - no query string, no body, only
  the expected user agent. Proven against an id appended by the caller, an
  extra header, and an id folded into the user agent.
- `agent/runtime/no_call_home_test.go` does the source scan for the agent,
  which runs on routers inside NetGrip, with no allowed list at all.

All three are new files, so none can conflict with a sync. The request test
calls upstream's own start function; if upstream renames it, the test stops
compiling - loud, and a one-line fix, which is how a guard should fail.

They read source rather than asking the toolchain what it would link. The
first version did ask `go list -deps`, and a review showed what that misses: it
sees only the host platform with default build tags, so a file limited to
arm64, or behind a build tag, would re-link the ping into the real deploy
build while the check passed. Reading source ignores build constraints. Both
were proven against planted violations - a build-tagged file, an
arm64-only file, a MIPS-only file in the agent, the ping rebuilt without the
package, a bare reference to the switch - and against a clean tree. Each also
fails if it scans implausibly few files: an earlier version walked nothing at
all and passed every case, which is exactly how a guard fails silently.

If a sync trips one, `go test ./...` names the file. For the telemetry
package, remove the wiring and leave the package untouched.

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
router panel depends on it. The payload fields it gained here — the panel's
port, whether the panel serves HTTPS and the key of the certificate it
serves, and the uplink policy — are what the panel's own fork needs, and they
are not in a released agent yet, so that side builds with a Go workspace.

### Reaching a NetGrip panel on HTTPS

When a router has a NetGrip executor token, `applyViaNetGrip` hands a plan's
operations to the panel's `/api/executor/apply`, token attached. It used to
address the panel as `http://<host>:8080`, which was wrong twice over: NetGrip
has defaulted to 8090 since upstream #210, and a panel serving HTTPS refuses
plain HTTP - while the token, which lets this server change the router, went
in clear until it did.

It now uses the port and scheme the embedded agent reports. The panel's
certificate is self-signed, so the connection is pinned to the key the agent
reports (`panelSpki`, the SHA-256 of the served certificate's
SubjectPublicKeyInfo). The router page's link to the panel follows the same
scheme. All of it lives in fork-only files
(`internal/httpapi/netgrip_panel.go`, `agent/runtime/panel.go`) with one call
site in each upstream file.

Every doubtful case sends nothing, and the plan falls back to the agent's own
channel as when the panel does not answer:

- **Only the router's own agent counts** - the one whose slug is the router id,
  which is also the id the executor token was stored under. A first version
  matched agents by host name as well and took the first; a second agent
  claiming the same host name could report plain HTTP and get the token sent
  in clear. A review demonstrated it; a test now does.
- **A router with an agent needs a fresh report from it.** An old one may
  predate a change of scheme. Reports are persisted on every push, so this
  covers the window after this server restarts, until the agent's next push,
  and a **revoked or uninstalled** agent too: revoking forgets the report in
  memory but leaves both the persisted report and the executor token behind,
  and treating that as "no agent" sent the next plan's token in clear - a
  review demonstrated it. So only a router with no report anywhere keeps
  upstream's behaviour, an executor token and an address and nothing more,
  which upstream's own delegation tests depend on; refusing that case too, as
  a first version of this fix did, broke them. A failed lookup counts as
  stale.
- **HTTPS is reported from how the panel was started, separately from the
  key.** Deriving it from the key reported an HTTPS panel as plain HTTP until
  its certificate was open. HTTPS with no key yet sends nothing.
- No redirects are followed with the token, and no connection is kept open.

**What the pin is worth depends on the agent's channel.** With the agent
pushing over https and pinning this server's key (`NETPULSE_SERVER_FP`), the
report cannot be altered in transit and the pin is sound. Over plain http it
is not: the push is signed with a key derived from the token it carries, so
anyone who reads one can forge one, and could substitute the panel's key.
They would gain nothing new - on that same path the executor token already
crosses in clear, in the agent's backup uploads and at start-up
registration - but it means this change fully protects the token only once
the agent channel is on https. On a plain-http deployment it still stops a
passive listener from reading the token off each delegated plan.

**Deploy NetGrip before NetPulse.** A NetGrip from before this change, running
on `-https`, reports its port but not its scheme, and a new NetPulse would send
the token to that TLS port in plain http.

**MQTT propagation rides the same path.** Upstream's "Propagate to NetGrip"
(#843) sends the broker's host, user and **password** to each NetGrip router
as an `mqtt.configure` operation through `applyViaNetGrip`. Upstream sends it
over plain http to port 8080; here it takes the reported port and scheme and
the pinned connection, and every doubtful case sends nothing - the password
included.

**The SSH token fallback needs an agent report.** Upstream (#838) reads a
missing executor token from the router over SSH, and stores it. For a router
whose agent has never reported, upstream's plain http to port 8080 applies,
so that fallback would send a token in clear where nothing was sent before -
and keep doing so, since the token is then stored. `netgripTokenFor` runs the
fallback only when the router's agent has reported, so the token goes through
the pinned path; with no report, only a token already stored is used, as
before #838. One window remains: NetGrip registers its token alongside the
agent's first push, so a plan applied before that push has landed still
takes upstream's path. Nothing leaves unless something answers on port 8080,
which NetGrip's own default of 8090 does not.

Note that `applyViaNetGrip` only runs for routers registered over SSH:
`hostOfRouter` returns nothing for an `agent_only` router, whose plans already
travel over the agent's channel. The standalone `netpulse-agent` binary has
its own loopback delegation to a NetGrip at `127.0.0.1:8080`, with the same
two problems; it is left alone because NetGrip embeds the agent and retires
a standalone install, so the two are not run together.

### HTTPS for NetPulse itself

`docs/https.md` is the user-facing account. The pieces, each opt-in so
upstream's behaviour is unchanged until an admin turns it on:

- `server-go/internal/tlscert/ca.go`: the private CA (name-constrained root,
  self-renewing leaf with a stable key).
- `server-go/internal/tlsmode`: the HTTPS listener, the plain-HTTP modes, the
  confirm-over-HTTPS step, HSTS per mode, and `AgentTrust` - how every
  install path moves an agent to HTTPS.
- `server-go/internal/httpapi/https_settings.go` and
  `app/src/components/HttpsCard.tsx`: Settings > HTTPS.
- Agent: `tlspin` accepts CA pins and pin lists; `runtime.ProveServerKey`
  with `POST /api/agents/pair/hello` proves the server's key at pairing;
  `runtime.ServerTransport` is exported for NetGrip.

The agent half needs an agent release before NetGrip's upstream can use it;
until then NetGrip builds against this checkout through its local `go.work`,
as for the panel fields above.

**Do not rename the module path** in this fork: every internal import would
change, guaranteeing conflicts on every sync. The fix is to get those fields
upstream and released; upstream's `feat(agent): decouple agent version from
server release tag (#791)` makes that easier.
