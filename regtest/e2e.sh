#!/usr/bin/env bash
# End-to-end smoke test for electrs-neurai running against a regtest daemon.
#
# Assumes `docker-compose up` has already been run from this directory, so:
#   - neurai-daemon-regtest  is reachable on the bridge network as neurai-daemon
#   - electrs-neurai-regtest is listening on localhost:60401
#
# Exits non-zero on the first failure. Designed to be usable both locally and
# from CI once a Neurai regtest daemon image is published.

set -euo pipefail

COMPOSE="docker compose -f $(dirname "$0")/docker-compose.yml"
CLI="$COMPOSE exec -T neurai-daemon neurai-cli -regtest -rpcuser=regtest -rpcpassword=regtest"
ELECTRUM_ADDR="127.0.0.1:60401"

say()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31m✘ %s\033[0m\n' "$*"; exit 1; }
ok()   { printf '  \033[1;32m✓ %s\033[0m\n' "$*"; }

# ─── helpers ──────────────────────────────────────────────────────────────────

jrpc() {
    # jrpc METHOD [JSON_PARAMS]  — send a line-delimited Electrum JSON-RPC request.
    local method="$1"
    local params="${2:-[]}"
    printf '{"id":1,"method":"%s","params":%s}\n' "$method" "$params" \
        | timeout 5 nc -q 1 ${ELECTRUM_ADDR%:*} ${ELECTRUM_ADDR##*:}
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"
}

require_cmd nc
require_cmd jq

# ─── 1) Generate some blocks ──────────────────────────────────────────────────

say "Generating 101 regtest blocks (unlocks coinbase)"
ADDR=$($CLI getnewaddress)
$CLI generatetoaddress 101 "$ADDR" >/dev/null
HEIGHT=$($CLI getblockcount)
[[ "$HEIGHT" == "101" ]] || fail "expected height 101, got $HEIGHT"
ok "daemon at height $HEIGHT"

# ─── 2) Wait for electrs to catch up ──────────────────────────────────────────

say "Waiting for electrs-neurai to index the tip"
for i in {1..30}; do
    RESPONSE=$(jrpc blockchain.headers.subscribe || true)
    if [[ -n "$RESPONSE" ]]; then
        IDX_HEIGHT=$(echo "$RESPONSE" | jq -r '.result.height // empty')
        [[ "$IDX_HEIGHT" == "$HEIGHT" ]] && break
    fi
    sleep 1
done
[[ "${IDX_HEIGHT:-0}" == "$HEIGHT" ]] || fail "electrs did not reach height $HEIGHT within 30s (got: ${IDX_HEIGHT:-none})"
ok "electrs tip matches daemon tip ($IDX_HEIGHT)"

# ─── 3) Address → scripthash round-trip ───────────────────────────────────────

say "Testing blockchain.address.get_scripthash"
RESPONSE=$(jrpc blockchain.address.get_scripthash "[\"$ADDR\"]")
SH=$(echo "$RESPONSE" | jq -r '.result // empty')
[[ -n "$SH" ]] || fail "no scripthash returned for $ADDR"
ok "scripthash($ADDR) = $SH"

# ─── 4) Issue a test asset ────────────────────────────────────────────────────

say "Issuing asset TESTASSET"
TXID=$($CLI issue TESTASSET 1000 "$ADDR" "" 0 1 0)
ok "issued TESTASSET, txid prefix: ${TXID:0:16}…"

say "Mining 1 block to confirm issuance"
$CLI generatetoaddress 1 "$ADDR" >/dev/null
sleep 3

# ─── 5) blockchain.asset.get_meta ─────────────────────────────────────────────

say "Testing blockchain.asset.get_meta"
META=$(jrpc blockchain.asset.get_meta '["TESTASSET"]' | jq -r '.result')
[[ "$META" != "null" ]] || fail "get_meta returned null for TESTASSET"
AMOUNT=$(echo "$META" | jq -r '.amount')
EVENT=$(echo "$META" | jq -r '.event')
[[ "$EVENT" == "new" ]] || fail "expected event=new, got $EVENT"
ok "asset meta: event=$EVENT amount=$AMOUNT"

# ─── 6) blockchain.asset.get_history ──────────────────────────────────────────

say "Testing blockchain.asset.get_history"
HISTORY=$(jrpc blockchain.asset.get_history '["TESTASSET"]' | jq -r '.result')
COUNT=$(echo "$HISTORY" | jq 'length')
[[ "$COUNT" -ge 1 ]] || fail "expected >=1 history entry, got $COUNT"
ok "asset history: $COUNT entries"

# ─── 7) Mempool asset tracking ────────────────────────────────────────────────

say "Transferring asset (unconfirmed) to test mempool tracking"
NEW_ADDR=$($CLI getnewaddress)
$CLI transfer TESTASSET 10 "$NEW_ADDR" >/dev/null
sleep 3

HISTORY=$(jrpc blockchain.asset.get_history '["TESTASSET"]' | jq -r '.result')
UNCONF=$(echo "$HISTORY" | jq '[.[] | select(.height <= 0)] | length')
[[ "$UNCONF" -ge 1 ]] || fail "expected mempool entry after transfer"
ok "mempool transfer visible in history ($UNCONF unconfirmed entries)"

printf '\n\033[1;32mAll regtest checks passed.\033[0m\n'
