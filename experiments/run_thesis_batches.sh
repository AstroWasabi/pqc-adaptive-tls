#!/usr/bin/env bash
# experiments/run_thesis_batches.sh
# ═══════════════════════════════════════════════════════════════════════════
# Automated Master's Thesis Experiment Runner (5 Batches x 200 Iterations)
#
# Executes 5 batches of 200 measured handshakes (= 1,000 samples/suite/mode)
# with full pre-warmed client key pools, untimed warmups, and cooldown pauses
# between batches so the 2-core server replenishes during idle windows.
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${REPO_ROOT}/c_dispatch/bench_e2e"

HOST=""
PORT=4444
TAG="client_run"
MODE="interleaved"   # baseline | precomputed | interleaved
BATCHES=5
RUNS=200
WARMUP=5
COOLDOWN=15
KDF="sha256"

usage() {
    cat <<EOF
Usage: $0 --host <SERVER_IP> --tag <fedora_lan|ec2_wan> [OPTIONS]

Options:
  --host <IP>          Arch Linux server IP address (Required)
  --port <PORT>        Server port (default: 4444)
  --tag <NAME>         Output folder name under results/<NAME> (default: client_run)
  --mode <MODE>        'baseline', 'precomputed', or 'interleaved' (default: interleaved)
  --batches <B>        Number of batches (default: 5)
  --runs <R>           Iterations per batch (default: 200 -> 5x200 = 1000 total)
  --warmup <W>         Untimed warmup handshakes per suite/mode (default: 5)
  --cooldown <SEC>     Pause in seconds between runs for thermal & server refill (default: 15)
  --kdf <sha256|blake3>Session key KDF (default: sha256)
  -h, --help           Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)     HOST="$2"; shift 2 ;;
        --port)     PORT="$2"; shift 2 ;;
        --tag)      TAG="$2"; shift 2 ;;
        --mode)     MODE="$2"; shift 2 ;;
        --batches)  BATCHES="$2"; shift 2 ;;
        --runs)     RUNS="$2"; shift 2 ;;
        --warmup)   WARMUP="$2"; shift 2 ;;
        --cooldown) COOLDOWN="$2"; shift 2 ;;
        --kdf)      KDF="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *) echo "[!] Unknown argument: $1"; usage ;;
    esac
done

if [[ -z "${HOST}" ]]; then
    echo "[!] Error: --host <SERVER_IP> is required."
    usage
fi

if [[ ! -x "${BIN}" ]]; then
    echo "[!] ${BIN} not found. Building first..."
    (cd "${REPO_ROOT}/c_dispatch" && make all)
fi

OUT_DIR="${REPO_ROOT}/results/${TAG}"
mkdir -p "${OUT_DIR}"

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  Master's Thesis Batch Runner"
echo "  Target Server : ${HOST}:${PORT}"
echo "  Output Dir    : ${OUT_DIR}"
echo "  Schedule      : ${BATCHES} batches x ${RUNS} runs = $((BATCHES * RUNS)) handshakes/mode/suite"
echo "  Execution Mode: ${MODE} (Cooldown: ${COOLDOWN}s between runs)"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""

run_single() {
    local b="$1"
    local kind="$2"   # baseline or precomputed
    local extra_flag=()
    if [[ "${kind}" == "precomputed" ]]; then
        extra_flag=(--precompute)
    fi

    local json_out="${OUT_DIR}/batch_${b}_${kind}.json"
    local csv_out="${OUT_DIR}/batch_${b}_${kind}_raw.csv"

    local kind_upper
    kind_upper="$(echo "${kind}" | tr '[:lower:]' '[:upper:]')"
    echo ">>> [Batch ${b}/${BATCHES}] Running ${kind_upper} (${RUNS} runs/mode)..."
    "${BIN}" \
        --host "${HOST}" \
        --port "${PORT}" \
        --runs "${RUNS}" \
        --warmup "${WARMUP}" \
        --kdf "${KDF}" \
        "${extra_flag[@]}" \
        --out "${json_out}" \
        --raw-csv "${csv_out}"

    if [[ -f "host_profile.json" ]]; then
        cp -f "host_profile.json" "${OUT_DIR}/host_profile.json"
    fi
}

for (( b=1; b<=BATCHES; b++ )); do
    if [[ "${MODE}" == "baseline" ]]; then
        run_single "${b}" "baseline"
    elif [[ "${MODE}" == "precomputed" ]]; then
        run_single "${b}" "precomputed"
    elif [[ "${MODE}" == "interleaved" ]]; then
        # Counterbalanced AB / BA ordering across batches to cancel WAN RTT drift
        if (( b % 2 == 1 )); then
            run_single "${b}" "baseline"
            echo "[*] Cooling down & allowing server idle-window refill (${COOLDOWN}s)..."
            sleep "${COOLDOWN}"
            run_single "${b}" "precomputed"
        else
            run_single "${b}" "precomputed"
            echo "[*] Cooling down & allowing server idle-window refill (${COOLDOWN}s)..."
            sleep "${COOLDOWN}"
            run_single "${b}" "baseline"
        fi
    else
        echo "[!] Invalid --mode '${MODE}'. Must be baseline, precomputed, or interleaved."
        exit 1
    fi

    if (( b < BATCHES )); then
        echo "[*] Inter-batch cooldown (${COOLDOWN}s)..."
        sleep "${COOLDOWN}"
    fi
done

echo ""
echo "[✔] Completed ${BATCHES} batches for '${TAG}' (${MODE})."

# Automatically aggregate if both baseline and precomputed batches exist
if ls "${OUT_DIR}"/batch_*_baseline_raw.csv >/dev/null 2>&1 && \
   ls "${OUT_DIR}"/batch_*_precomputed_raw.csv >/dev/null 2>&1; then
    echo "[*] Aggregating all batches into pooled 1,000-run thesis summary..."
    python3 "${REPO_ROOT}/analysis/aggregate_thesis_results.py" "${OUT_DIR}"
fi
