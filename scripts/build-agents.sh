#!/usr/bin/env bash
# Builds the five netpulse-agent binaries, packs them with UPX and verifies
# the result. Single source of truth for the local build (Makefile) and the
# three workflows that need embedded agents (pr, go-latest, release).
#
# Usage: scripts/build-agents.sh <agent-version> [output-dir]
#
#   UPX_BIN            upx binary to use (default: upx from PATH)
#   UPX_FLAGS          packing flags (default: --best --lzma)
#   GO                 go binary (default: go from PATH)
#   NETPULSE_AGENT_UPX 1 (default) packs; 0 leaves the binaries unpacked,
#                      for a build host without upx. An unpacked agent is
#                      7-9 MB and needs twice that free on a router to
#                      upgrade, so only use it when no small router takes
#                      its agent from this server. The choice is recorded in
#                      agent.packing next to the binaries.
#
# The packed binaries are the ones served by /api/agents/{slug}/binary and
# shipped in the release tarballs, so their sha256 (computed by the server at
# runtime over the embedded bytes) matches what the installer verifies.
set -euo pipefail

VERSION=${1:?usage: build-agents.sh <agent-version> [output-dir]}
OUT=${2:-server-go/internal/agentbin/agents}
UPX_BIN=${UPX_BIN:-upx}
UPX_FLAGS=${UPX_FLAGS:---best --lzma}
PACK=${NETPULSE_AGENT_UPX:-1}
case "$PACK" in
	0 | 1) ;;
	*)
		echo "build-agents: NETPULSE_AGENT_UPX must be 0 or 1, got '$PACK'" >&2
		exit 1
		;;
esac
GO=${GO:-go}

cd "$(dirname "$0")/.."

if [ "$PACK" = 1 ] && ! command -v "$UPX_BIN" >/dev/null 2>&1; then
	echo "build-agents: $UPX_BIN is not in PATH. Install it (pacman -S upx, apt install upx-ucl," >&2
	echo "  dnf install upx) or point UPX_BIN at the binary. The agents are UPX packed on" >&2
	echo "  purpose: an unpacked agent needs twice its size free to upgrade (#1890)." >&2
	echo "  NETPULSE_AGENT_UPX=0 builds them unpacked instead." >&2
	exit 1
fi

mkdir -p "$OUT"
export CGO_ENABLED=0
export GOOS=linux

build() {
	local arch=$1 extra=$2
	# go build does not always rewrite an existing -o target when the build is
	# cached, and a target that is already UPX packed makes the packing step
	# fail with AlreadyPackedException. Removing it first keeps the script
	# idempotent: two runs in a row must both work.
	rm -f "$OUT/netpulse-agent-$arch"
	# shellcheck disable=SC2086
	(cd agent && env GOARCH="$arch" $extra "$GO" build -trimpath \
		-ldflags "-s -w -X main.Version=$VERSION" \
		-o "../$OUT/netpulse-agent-$arch" ./cmd/netpulse-agent)
}

# armv7 is "arm" with GOARM=7; MIPS (MT7621, ath79) has no FPU: softfloat.
build amd64 ""
build arm64 ""
build arm "GOARM=7"
build mipsle "GOMIPS=softfloat"
build mips "GOMIPS=softfloat"

if [ "$PACK" = 1 ]; then
	# shellcheck disable=SC2086: the flags are a list on purpose
	"$UPX_BIN" -q -f $UPX_FLAGS "$OUT"/netpulse-agent-* >/dev/null
fi

# Gate: every binary must be packed, pass UPX's own integrity test and stay
# well under the unpacked size. An unpacked release is a regression of #1890,
# and a silently skipped UPX (goreleaser skips it when it is not in PATH)
# would only show up as a failed upgrade on a router with little storage.
for arch in amd64 arm64 arm mipsle mips; do
	bin="$OUT/netpulse-agent-$arch"
	[ -s "$bin" ] || { echo "build-agents: missing $bin" >&2; exit 1; }
	[ "$PACK" = 1 ] || continue
	# UPX keeps a valid ELF header and writes its marker at the tail.
	if ! tail -c 256 "$bin" | grep -qa "UPX!"; then
		echo "build-agents: $bin is not UPX packed" >&2
		exit 1
	fi
	"$UPX_BIN" -t "$bin" >/dev/null || { echo "build-agents: $bin fails the UPX integrity test" >&2; exit 1; }
done

# UPX compresses the version literal passed with -X main.Version, so the #1246
# guard cannot find it by scanning the embedded bytes. The stamp keeps that
# check working without unpacking at runtime (#1914).
printf '%s\n' "$VERSION" > "$OUT/agent.version"
# Whether the binaries were packed: the agentbin test checks packing only
# for a build that says it packed.
if [ "$PACK" = 1 ]; then echo upx; else echo none; fi > "$OUT/agent.packing"

ls -l "$OUT"/netpulse-agent-*
