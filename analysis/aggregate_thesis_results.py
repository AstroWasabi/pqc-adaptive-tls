#!/usr/bin/env python3
"""
analysis/aggregate_thesis_results.py
═══════════════════════════════════════════════════════════════════════════
Aggregates multi-batch raw CSV & JSON benchmark outputs (e.g., 5 x 200 = 1,000
handshakes per mode/suite) into pooled statistics + inter-batch 95% CIs for
Master's thesis tables and figures. Uses zero external dependencies (pure stdlib).
═══════════════════════════════════════════════════════════════════════════
"""

import csv
import glob
import json
import math
import os
import sys
from collections import defaultdict


# Two-sided 95% Student-t critical values by degrees of freedom (B - 1)
T_CRIT_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447,  7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228
}


def compute_dist_stats(values):
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "stddev": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    s = sorted(values)
    mean = sum(s) / n
    var = sum((x - mean) ** 2 for x in s) / (n - 1) if n > 1 else 0.0
    return {
        "mean": mean,
        "stddev": math.sqrt(var),
        "p50": s[int((n - 1) * 0.50)],
        "p95": s[int((n - 1) * 0.95)],
        "p99": s[int((n - 1) * 0.99)],
    }


def compute_interbatch_ci(batch_medians):
    b = len(batch_medians)
    if b == 0:
        return {"batch_count": 0, "mean_of_p50": 0.0, "sd_of_p50": 0.0, "ci95_halfwidth": 0.0}
    mean_m = sum(batch_medians) / b
    if b == 1:
        return {"batch_count": 1, "mean_of_p50": mean_m, "sd_of_p50": 0.0, "ci95_halfwidth": 0.0}
    var_m = sum((x - mean_m) ** 2 for x in batch_medians) / (b - 1)
    sd_m = math.sqrt(var_m)
    t_val = T_CRIT_95.get(b - 1, 1.96)
    ci95 = t_val * (sd_m / math.sqrt(b))
    return {
        "batch_count": b,
        "mean_of_p50": mean_m,
        "sd_of_p50": sd_m,
        "ci95_halfwidth": ci95,
    }


def load_kind(result_dir, kind):
    """Loads all batch_*_<kind>_raw.csv files and returns pooled + per-batch metrics."""
    pattern = os.path.join(result_dir, f"batch_*_{kind}_raw.csv")
    csv_files = sorted(glob.glob(pattern))
    if not csv_files:
        return None

    pooled = defaultdict(lambda: {"ch": [], "post": [], "wire": [], "tot": [], "hits": 0, "routes": []})
    per_batch_tot = defaultdict(list)
    per_batch_wire = defaultdict(list)
    suite_order = []

    for fpath in csv_files:
        batch_rows = defaultdict(list)
        batch_wires = defaultdict(list)
        with open(fpath, "r", newline="") as fp:
            reader = csv.DictReader(fp)
            for row in reader:
                suite = row["cipher_suite"]
                mode = row["mode"]
                key = (suite, mode)
                if key not in suite_order:
                    suite_order.append(key)

                ch = float(row["ch_prep_ms"])
                post = float(row["post_sh_ms"])
                wire = float(row["wire_ms"])
                tot = float(row["total_ms"])
                hit = int(row["pool_hit"])

                d = pooled[key]
                d["ch"].append(ch)
                d["post"].append(post)
                d["wire"].append(wire)
                d["tot"].append(tot)
                d["hits"] += hit
                d["routes"].append(row["selected_route"])

                batch_rows[key].append(tot)
                batch_wires[key].append(wire)

        for key, vals in batch_rows.items():
            s = sorted(vals)
            per_batch_tot[key].append(s[int((len(s) - 1) * 0.50)])
        for key, wvals in batch_wires.items():
            sw = sorted(wvals)
            per_batch_wire[key].append(sw[int((len(sw) - 1) * 0.50)])

    records = []
    for key in suite_order:
        suite, mode = key
        d = pooled[key]
        n = len(d["tot"])
        par_votes = sum(1 for r in d["routes"] if r == "Parallel")
        sel_route = "Parallel" if par_votes * 2 >= n else "Sequential"

        ch_s = compute_dist_stats(d["ch"])
        post_s = compute_dist_stats(d["post"])
        wire_s = compute_dist_stats(d["wire"])
        tot_s = compute_dist_stats(d["tot"])
        batch_ci = compute_interbatch_ci(per_batch_tot[key])
        wire_ci = compute_interbatch_ci(per_batch_wire[key])

        records.append({
            "cipher_suite": suite,
            "mode": mode,
            "selected_route": sel_route,
            "total_pooled_runs": n,
            "num_batches": batch_ci["batch_count"],
            "pool_hit_rate": (d["hits"] / n) * 100.0 if n else 0.0,
            "ch_prep_p50_ms": round(ch_s["p50"], 6),
            "ch_prep_p95_ms": round(ch_s["p95"], 6),
            "ch_prep_p99_ms": round(ch_s["p99"], 6),
            "ch_prep_mean_ms": round(ch_s["mean"], 6),
            "ch_prep_stddev_ms": round(ch_s["stddev"], 6),
            "post_sh_p50_ms": round(post_s["p50"], 6),
            "post_sh_p95_ms": round(post_s["p95"], 6),
            "post_sh_p99_ms": round(post_s["p99"], 6),
            "post_sh_mean_ms": round(post_s["mean"], 6),
            "post_sh_stddev_ms": round(post_s["stddev"], 6),
            "wire_p50_ms": round(wire_s["p50"], 6),
            "wire_mean_ms": round(wire_s["mean"], 6),
            "wire_batch_ci95_ms": round(wire_ci["ci95_halfwidth"], 6),
            "total_p50_ms": round(tot_s["p50"], 6),
            "total_p95_ms": round(tot_s["p95"], 6),
            "total_p99_ms": round(tot_s["p99"], 6),
            "total_mean_ms": round(tot_s["mean"], 6),
            "total_stddev_ms": round(tot_s["stddev"], 6),
            "batch_p50_mean_ms": round(batch_ci["mean_of_p50"], 6),
            "batch_p50_sd_ms": round(batch_ci["sd_of_p50"], 6),
            "batch_p50_ci95_ms": round(batch_ci["ci95_halfwidth"], 6),
        })
    return records


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results_subfolder>")
        sys.exit(1)

    res_dir = sys.argv[1]
    base_recs = load_kind(res_dir, "baseline")
    prec_recs = load_kind(res_dir, "precomputed")

    if not base_recs and not prec_recs:
        print(f"[!] No batch_*_raw.csv files found in {res_dir}")
        sys.exit(1)

    summary = {}
    if base_recs:
        summary["baseline"] = base_recs
        with open(os.path.join(res_dir, "e2e_results_baseline.json"), "w") as fp:
            json.dump(base_recs, fp, indent=2)
    if prec_recs:
        summary["precomputed"] = prec_recs
        with open(os.path.join(res_dir, "e2e_results_precomputed.json"), "w") as fp:
            json.dump(prec_recs, fp, indent=2)

    host_prof_path = os.path.join(res_dir, "host_profile.json")
    if os.path.exists(host_prof_path):
        with open(host_prof_path, "r") as fp:
            summary["host_profile"] = json.load(fp)

    out_summary = os.path.join(res_dir, "thesis_summary_1000.json")
    with open(out_summary, "w") as fp:
        json.dump(summary, fp, indent=2)

    print("\n" + "═" * 98)
    print(f"  POOLED THESIS SUMMARY ({res_dir})")
    print("═" * 98)

    if base_recs and prec_recs:
        base_map = {(r["cipher_suite"], r["mode"]): r for r in base_recs}
        prec_map = {(r["cipher_suite"], r["mode"]): r for r in prec_recs}
        suites = []
        for r in base_recs:
            if r["cipher_suite"] not in suites:
                suites.append(r["cipher_suite"])

        print(f"{'Cipher Suite':<34} | {'Base Seq (ms)':<14} | {'Combined (ms)':<14} | {'Batch ±95%CI':<14} | {'Delta / Cut'}")
        print("-" * 98)
        for s in suites:
            b_seq = base_map.get((s, "Strict_Sequential"))
            p_ada = prec_map.get((s, "Adaptive_Switch")) or prec_map.get((s, "Strict_Parallel"))
            if b_seq and p_ada:
                b_tot = b_seq["total_p50_ms"]
                p_tot = p_ada["total_p50_ms"]
                diff = b_tot - p_tot
                pct = (diff / b_tot * 100.0) if b_tot > 0 else 0.0
                ci = p_ada["batch_p50_ci95_ms"]
                print(f"{s:<34} | {b_tot:>10.3f} ms | {p_tot:>10.3f} ms | ±{ci:>8.3f} ms  | -{diff:.3f} ms ({pct:.1f}%)")
        print("═" * 98)

    print(f"[✔] Saved pooled JSONs -> {out_summary}")
    print(f"                       -> {os.path.join(res_dir, 'e2e_results_baseline.json')}")
    print(f"                       -> {os.path.join(res_dir, 'e2e_results_precomputed.json')}\n")


if __name__ == "__main__":
    main()
