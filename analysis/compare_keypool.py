#!/usr/bin/env python3
"""
compare_keypool.py
Compares end-to-end TLS 1.3 handshake latency between:
  1. Baseline (On-Demand Key Generation)
  2. Optimized (Pre-Computed Ephemeral Key Pool)

Usage:
    python3 compare_keypool.py e2e_baseline.json e2e_precomputed.json
"""

import sys
import json

def load_results(path):
    with open(path, 'r') as f:
        data = json.load(f)
    # Map (combo, mode) -> stats
    res = {}
    for item in data:
        key = (item["combo"], item["mode"])
        res[key] = item
    return res

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 compare_keypool.py <e2e_baseline.json> <e2e_precomputed.json>")
        sys.exit(1)

    base_path = sys.argv[1]
    prep_path = sys.argv[2]

    base = load_results(base_path)
    prep = load_results(prep_path)

    print("\n" + "=" * 95)
    print("      E2E TLS 1.3 HYBRID HANDSHAKE LATENCY: BASELINE vs. PRE-COMPUTED KEY POOL")
    print("=" * 95)

    combos = list(dict.fromkeys([k[0] for k in base.keys()]))

    for combo in combos:
        print(f"\n### {combo}")
        print("-" * 95)
        print(f"{'Mode':<18} | {'Metric':<6} | {'Baseline (ms)':<14} | {'Precomputed (ms)':<16} | {'Savings':<12} | {'Speedup':<8}")
        print("-" * 95)

        for mode in ["Strict_Sequential", "Strict_Parallel", "Adaptive_Switch"]:
            key = (combo, mode)
            if key not in base or key not in prep:
                continue

            b_stat = base[key]
            p_stat = prep[key]

            # Mean
            b_mean = b_stat["mean_ms"]
            p_mean = p_stat["mean_ms"]
            diff_mean = b_mean - p_mean
            pct_mean = (diff_mean / b_mean) * 100 if b_mean > 0 else 0

            # p50
            b_p50 = b_stat["p50_ms"]
            p_p50 = p_stat["p50_ms"]
            diff_p50 = b_p50 - p_p50
            pct_p50 = (diff_p50 / b_p50) * 100 if b_p50 > 0 else 0

            # p99
            b_p99 = b_stat["p99_ms"]
            p_p99 = p_stat["p99_ms"]
            diff_p99 = b_p99 - p_p99
            pct_p99 = (diff_p99 / b_p99) * 100 if b_p99 > 0 else 0

            print(f"{mode:<18} | Mean   | {b_mean:>12.4f} ms | {p_mean:>14.4f} ms | {diff_mean:>9.4f} ms | {pct_mean:>6.1f}%")
            print(f"{'':<18} | p50    | {b_p50:>12.4f} ms | {p_p50:>14.4f} ms | {diff_p50:>9.4f} ms | {pct_p50:>6.1f}%")
            print(f"{'':<18} | p99    | {b_p99:>12.4f} ms | {p_p99:>14.4f} ms | {diff_p99:>9.4f} ms | {pct_p99:>6.1f}%")
            print("-" * 95)

    print("\n" + "=" * 95)
    print("  Summary: Key pool eliminates the client-side TCP-to-TLS keygen preparation phase.")
    print("  Combined with adaptive parallel dispatch, both keygen and in-flight stalls are mitigated.")
    print("=" * 95 + "\n")

if __name__ == "__main__":
    main()
