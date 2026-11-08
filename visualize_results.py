#!/usr/bin/env python3
"""
Publication-Quality Visualizations for Hybrid PQC TLS 1.3 Benchmark
====================================================================
Designed for Master's Thesis Progress Meeting & Papers.

Produces 4 publication-grade figures:
  1. Figure 1: Phase A (ClientHello Prep): Inline Keygen vs Dual Key Pool Precomputation
  2. Figure 2: Phase B (Post-ServerHello): Sequential vs Parallel Interactive Derivation
  3. Figure 3: Full End-to-End Handshake Latency across the 4 Execution Strategies
  4. Figure 4: Stacked Latency Breakdown (Phase A Keygen + Phase B Crypto + Network Wire)
"""

import os
import json
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

# ─── Aesthetics & Styling ──────────────────────────────────────────────────
plt.rcParams['font.sans-serif'] = 'Helvetica', 'Arial', 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#333333'
plt.rcParams['axes.linewidth'] = 0.8
plt.rcParams['grid.color'] = '#e0e0e0'
plt.rcParams['grid.linestyle'] = '--'
plt.rcParams['grid.alpha'] = 0.7

SUITE_LABELS = [
    "X25519 +\nML-KEM-768",
    "SecP256r1 +\nML-KEM-768",
    "SecP384r1 +\nML-KEM-1024",
    "SecP384r1 +\nFrodoKEM-1344",
    "SecP384r1 +\nBIKE-L5"
]

SUITE_KEYS = [
    "Hybrid: X25519 + ML-KEM-768",
    "Hybrid: SecP256r1 + ML-KEM-768",
    "Hybrid: SecP384r1 + ML-KEM-1024",
    "Hybrid: SecP384r1 + FrodoKEM-1344",
    "Hybrid: SecP384r1 + BIKE-L5"
]

# Exact empirical benchmark data from local run (p50 latencies in ms)
BENCHMARK_DATA = {
    "baseline": {
        "Hybrid: X25519 + ML-KEM-768": {
            "Strict_Sequential": {"ch_prep": 0.1394, "post_sh": 0.1088, "total": 0.5255},
            "Strict_Parallel":   {"ch_prep": 0.1361, "post_sh": 0.1062, "total": 0.5080},
            "Adaptive_Switch":   {"ch_prep": 0.1170, "post_sh": 0.1068, "total": 0.4852},
        },
        "Hybrid: SecP256r1 + ML-KEM-768": {
            "Strict_Sequential": {"ch_prep": 0.1535, "post_sh": 0.2764, "total": 0.9088},
            "Strict_Parallel":   {"ch_prep": 0.1725, "post_sh": 0.2831, "total": 0.9223},
            "Adaptive_Switch":   {"ch_prep": 0.1728, "post_sh": 0.2760, "total": 0.9235},
        },
        "Hybrid: SecP384r1 + ML-KEM-1024": {
            "Strict_Sequential": {"ch_prep": 0.4396, "post_sh": 1.2819, "total": 3.4950},
            "Strict_Parallel":   {"ch_prep": 0.4385, "post_sh": 1.2819, "total": 3.4893},
            "Adaptive_Switch":   {"ch_prep": 0.4407, "post_sh": 1.2823, "total": 3.4981},
        },
        "Hybrid: SecP384r1 + FrodoKEM-1344": {
            "Strict_Sequential": {"ch_prep": 2.2886, "post_sh": 3.7102, "total": 10.3011},
            "Strict_Parallel":   {"ch_prep": 1.9374, "post_sh": 2.6507, "total": 8.8967},
            "Adaptive_Switch":   {"ch_prep": 2.2869, "post_sh": 3.7039, "total": 10.2987},
        },
        "Hybrid: SecP384r1 + BIKE-L5": {
            "Strict_Sequential": {"ch_prep": 2.6657, "post_sh": 8.9503, "total": 13.6793},
            "Strict_Parallel":   {"ch_prep": 2.3915, "post_sh": 7.7702, "total": 12.2292},
            "Adaptive_Switch":   {"ch_prep": 2.6753, "post_sh": 8.9302, "total": 13.6692},
        },
    },
    "precomputed": {
        "Hybrid: X25519 + ML-KEM-768": {
            "Strict_Sequential": {"ch_prep": 0.1135, "post_sh": 0.1068, "total": 0.4725},
            "Strict_Parallel":   {"ch_prep": 0.1855, "post_sh": 0.1586, "total": 0.6105},
            "Adaptive_Switch":   {"ch_prep": 0.1848, "post_sh": 0.1643, "total": 0.6130},
        },
        "Hybrid: SecP256r1 + ML-KEM-768": {
            "Strict_Sequential": {"ch_prep": 0.0239, "post_sh": 0.2755, "total": 0.8314},
            "Strict_Parallel":   {"ch_prep": 0.0165, "post_sh": 0.2838, "total": 0.8585},
            "Adaptive_Switch":   {"ch_prep": 0.0165, "post_sh": 0.2760, "total": 0.8524},
        },
        "Hybrid: SecP384r1 + ML-KEM-1024": {
            "Strict_Sequential": {"ch_prep": 0.0164, "post_sh": 1.2813, "total": 3.1254},
            "Strict_Parallel":   {"ch_prep": 0.0168, "post_sh": 1.2812, "total": 3.1283},
            "Adaptive_Switch":   {"ch_prep": 0.0168, "post_sh": 1.2817, "total": 3.1312},
        },
        "Hybrid: SecP384r1 + FrodoKEM-1344": {
            "Strict_Sequential": {"ch_prep": 0.0298, "post_sh": 3.6765, "total": 8.0454},
            "Strict_Parallel":   {"ch_prep": 0.0220, "post_sh": 2.6331, "total": 7.0057},
            "Adaptive_Switch":   {"ch_prep": 0.0219, "post_sh": 3.6736, "total": 8.0429},
        },
        "Hybrid: SecP384r1 + BIKE-L5": {
            "Strict_Sequential": {"ch_prep": 0.0267, "post_sh": 8.7891, "total": 10.9137},
            "Strict_Parallel":   {"ch_prep": 0.0194, "post_sh": 7.7782, "total": 9.9231},
            "Adaptive_Switch":   {"ch_prep": 0.0181, "post_sh": 8.8072, "total": 10.9419},
        },
    }
}

def load_data():
    """Load from JSON if present, else fallback to embedded data."""
    data = {"baseline": {}, "precomputed": {}}
    for tag in ["baseline", "precomputed"]:
        path = f"e2e_results_{tag}.json"
        if os.path.exists(path):
            with open(path) as f:
                entries = json.load(f)
                for e in entries:
                    cs = e["cipher_suite"]
                    m = e["mode"]
                    if cs not in data[tag]: data[tag][cs] = {}
                    data[tag][cs][m] = {
                        "ch_prep": e["ch_prep_p50_ms"],
                        "post_sh": e["post_sh_p50_ms"],
                        "total": e["total_p50_ms"]
                    }
        else:
            data[tag] = BENCHMARK_DATA[tag]
    return data

DATA = load_data()

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 1: Phase A (ClientHello Prep Latency) — Precompute Impact
# ═══════════════════════════════════════════════════════════════════════════
def plot_figure1_phase_a():
    x = np.arange(len(SUITE_KEYS))
    width = 0.35

    inline_prep = [DATA["baseline"][k]["Strict_Sequential"]["ch_prep"] for k in SUITE_KEYS]
    precomp_prep = [DATA["precomputed"][k]["Strict_Sequential"]["ch_prep"] for k in SUITE_KEYS]

    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=150)
    rects1 = ax.bar(x - width/2, inline_prep, width, label='Baseline (Inline Keygen)',
                    color='#d9534f', edgecolor='#333333', linewidth=0.8)
    rects2 = ax.bar(x + width/2, precomp_prep, width, label='Precomputed Dual Key Pool (Ours)',
                    color='#2b8a3e', edgecolor='#333333', linewidth=0.8)

    ax.set_ylabel('Client Preparation Latency (ms)', fontsize=11, fontweight='bold')
    ax.set_title('Figure 1: Phase A ClientHello Prep Latency (Inline vs. Dual Key Pool)',
                 fontsize=13, fontweight='bold', pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(SUITE_LABELS, fontsize=10)
    ax.legend(frameon=True, facecolor='#ffffff', edgecolor='#cccccc', fontsize=10)
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # Annotate speedup factors
    for i in range(len(SUITE_KEYS)):
        speedup = inline_prep[i] / precomp_prep[i]
        ax.annotate(f"{speedup:.1f}x faster\n({inline_prep[i]:.2f}ms to {precomp_prep[i]*1000:.0f}us)",
                    xy=(x[i] + width/2, precomp_prep[i]),
                    xytext=(x[i] + 0.05, inline_prep[i] * 0.75 if inline_prep[i] > 1.0 else inline_prep[i] + 0.15),
                    fontsize=8.5, fontweight='bold', color='#1e5622',
                    bbox=dict(boxstyle="round,pad=0.25", fc="#ebfbee", ec="#2b8a3e", lw=0.8))

    plt.tight_layout()
    plt.savefig('fig1_phase_a_precompute.png', dpi=300)
    plt.close()

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 2: Phase B (Interactive Derivation) — Parallel Speedup
# ═══════════════════════════════════════════════════════════════════════════
def plot_figure2_phase_b():
    x = np.arange(len(SUITE_KEYS))
    width = 0.35

    seq_b = [DATA["precomputed"][k]["Strict_Sequential"]["post_sh"] for k in SUITE_KEYS]
    par_b = [DATA["precomputed"][k]["Strict_Parallel"]["post_sh"] for k in SUITE_KEYS]

    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=150)
    rects1 = ax.bar(x - width/2, seq_b, width, label='Sequential Phase B',
                    color='#4a69bd', edgecolor='#333333', linewidth=0.8)
    rects2 = ax.bar(x + width/2, par_b, width, label='Core-Pinned Parallel Phase B (Ours)',
                    color='#1e3799', edgecolor='#333333', linewidth=0.8)

    ax.set_ylabel('Post-ServerHello Crypto Latency (ms)', fontsize=11, fontweight='bold')
    ax.set_title('Figure 2: Phase B Interactive Latency (Sequential vs. Parallel Concurrency)',
                 fontsize=13, fontweight='bold', pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(SUITE_LABELS, fontsize=10)
    ax.legend(frameon=True, facecolor='#ffffff', edgecolor='#cccccc', fontsize=10)
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    # Annotate parallel gains on heavy suites
    for i in [3, 4]:
        savings = seq_b[i] - par_b[i]
        pct = (savings / seq_b[i]) * 100
        ax.annotate(f"-{savings:.2f} ms\n({pct:.1f}% faster)",
                    xy=(x[i] + width/2, par_b[i]),
                    xytext=(x[i] - 0.15, par_b[i] + 0.6),
                    fontsize=8.5, fontweight='bold', color='#0c2461',
                    bbox=dict(boxstyle="round,pad=0.25", fc="#e8f0fe", ec="#1e3799", lw=0.8))

    plt.tight_layout()
    plt.savefig('fig2_phase_b_parallel.png', dpi=300)
    plt.close()

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 3: Complete Comparison of 4 Strategies on Level 5 Suites
# ═══════════════════════════════════════════════════════════════════════════
def plot_figure3_strategies_level5():
    suites = ["SecP384r1 + FrodoKEM-1344", "SecP384r1 + BIKE-L5"]
    keys = ["Hybrid: SecP384r1 + FrodoKEM-1344", "Hybrid: SecP384r1 + BIKE-L5"]

    strategies = [
        "1. Baseline Sequential",
        "2. Parallel Alone",
        "3. Precompute Alone",
        "4. Combined (Precompute + Parallel)"
    ]

    values = [
        [
            DATA["baseline"][keys[0]]["Strict_Sequential"]["total"],
            DATA["baseline"][keys[0]]["Strict_Parallel"]["total"],
            DATA["precomputed"][keys[0]]["Strict_Sequential"]["total"],
            DATA["precomputed"][keys[0]]["Strict_Parallel"]["total"]
        ],
        [
            DATA["baseline"][keys[1]]["Strict_Sequential"]["total"],
            DATA["baseline"][keys[1]]["Strict_Parallel"]["total"],
            DATA["precomputed"][keys[1]]["Strict_Sequential"]["total"],
            DATA["precomputed"][keys[1]]["Strict_Parallel"]["total"]
        ]
    ]

    x = np.arange(len(suites))
    width = 0.20
    colors = ['#e74c3c', '#e67e22', '#2980b9', '#27ae60']

    fig, ax = plt.subplots(figsize=(9, 5.2), dpi=150)
    for idx, strat in enumerate(strategies):
        offsets = x + (idx - 1.5) * width
        vals = [values[0][idx], values[1][idx]]
        bars = ax.bar(offsets, vals, width, label=strat, color=colors[idx],
                      edgecolor='#2c3e50', linewidth=0.8)
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f"{height:.2f}ms",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha='center', va='bottom', fontsize=8.5, fontweight='bold')

    ax.set_ylabel('Total Handshake Latency (ms)', fontsize=11, fontweight='bold')
    ax.set_title('Figure 3: Total Handshake Latency across Optimization Strategies (NIST Level 5)',
                 fontsize=13, fontweight='bold', pad=14)
    ax.set_xticks(x)
    ax.set_xticklabels(suites, fontsize=11, fontweight='bold')
    ax.set_ylim(0, 16.5)
    ax.legend(frameon=True, facecolor='#ffffff', edgecolor='#cccccc', fontsize=9.5, loc='upper left')
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig('fig3_optimization_strategies.png', dpi=300)
    plt.close()

# ═══════════════════════════════════════════════════════════════════════════
# FIGURE 4: Stacked Handshake Breakdown (Phase A vs Phase B vs Wire)
# ═══════════════════════════════════════════════════════════════════════════
def plot_figure4_stacked_breakdown():
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), dpi=150)
    keys = ["Hybrid: SecP384r1 + FrodoKEM-1344", "Hybrid: SecP384r1 + BIKE-L5"]
    titles = ["FrodoKEM-1344 Handshake Anatomy", "BIKE-L5 Handshake Anatomy"]
    modes = ["Seq Base", "Par Base", "Precomp Seq", "Precomp Par"]

    for ax_idx, (k, title) in enumerate(zip(keys, titles)):
        ax = axes[ax_idx]
        ch = [
            DATA["baseline"][k]["Strict_Sequential"]["ch_prep"],
            DATA["baseline"][k]["Strict_Parallel"]["ch_prep"],
            DATA["precomputed"][k]["Strict_Sequential"]["ch_prep"],
            DATA["precomputed"][k]["Strict_Parallel"]["ch_prep"],
        ]
        post = [
            DATA["baseline"][k]["Strict_Sequential"]["post_sh"],
            DATA["baseline"][k]["Strict_Parallel"]["post_sh"],
            DATA["precomputed"][k]["Strict_Sequential"]["post_sh"],
            DATA["precomputed"][k]["Strict_Parallel"]["post_sh"],
        ]
        total = [
            DATA["baseline"][k]["Strict_Sequential"]["total"],
            DATA["baseline"][k]["Strict_Parallel"]["total"],
            DATA["precomputed"][k]["Strict_Sequential"]["total"],
            DATA["precomputed"][k]["Strict_Parallel"]["total"],
        ]
        wire = [total[i] - (ch[i] + post[i]) for i in range(4)]

        p1 = ax.bar(modes, ch, color='#e74c3c', edgecolor='#333333', lw=0.8, label='Phase A: Keygen (ClientHello)')
        p2 = ax.bar(modes, post, bottom=ch, color='#3498db', edgecolor='#333333', lw=0.8, label='Phase B: Interactive Crypto')
        bottom_sum = [ch[i] + post[i] for i in range(4)]
        p3 = ax.bar(modes, wire, bottom=bottom_sum, color='#bdc3c7', edgecolor='#333333', lw=0.8, label='Network / Server Round Trip')

        ax.set_title(title, fontsize=12, fontweight='bold', pad=10)
        ax.set_ylabel('Latency (ms)' if ax_idx == 0 else '', fontsize=10, fontweight='bold')
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        if ax_idx == 0:
            ax.legend(loc='upper right', fontsize=8.5, frameon=True)

    plt.suptitle('Figure 4: Two-Phase Decomposition of TLS 1.3 Hybrid Key Exchange',
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()
    plt.savefig('fig4_stacked_breakdown.png', dpi=300)
    plt.close()

if __name__ == '__main__':
    print("Generating Figure 1: Phase A Precomputation Impact...")
    plot_figure1_phase_a()
    print("Generating Figure 2: Phase B Interactive Parallel Concurrency...")
    plot_figure2_phase_b()
    print("Generating Figure 3: Four-Strategy Comparison for NIST Level 5...")
    plot_figure3_strategies_level5()
    print("Generating Figure 4: Stacked Handshake Anatomy Breakdown...")
    plot_figure4_stacked_breakdown()
    print("\n[✔] All figures generated successfully in high-resolution PNG format.")
