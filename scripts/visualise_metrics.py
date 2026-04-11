#!/usr/bin/env python3
from pathlib import Path
 
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
import numpy as np
import sqlite3
 
# Project paths
DATA_DIR  = Path(__file__).resolve().parent.parent / "data"
PLOTS_DIR = DATA_DIR / "plots"
PLOTS_DIR.mkdir(parents=True, exist_ok=True)
 
C_TRAD  = "#26215F"   #Traditional VM
C_CTEM  = "#90D541"   #CTEM
COLORS  = [C_TRAD, C_CTEM]
ALPHA   = 0.85
 
#shared helpers
def load_csvs():
    """Load and normalise all three CSVs. Returns (metrics_df, attacks_df, exposures_df)."""
    metrics   = pd.read_csv(DATA_DIR / "metrics_summary.csv")
    attacks   = pd.read_csv(DATA_DIR / "attack_simulations.csv")
    exposures = pd.read_csv(DATA_DIR / "exposures.csv")
 
    for df in [metrics, attacks, exposures]:
        df.columns = df.columns.str.strip()
 
    metrics["workflow"]           = metrics["workflow"].str.strip()
    attacks["workflow_type"]      = attacks["workflow_type"].str.strip()
    exposures["workflow_type"]    = exposures["workflow_type"].str.strip()
    exposures["severity"]         = exposures["severity"].str.strip()
 
    # Ensure iteration_id is numeric (guards against "iter_1" style strings)
    for df in [attacks, exposures]:
        df["iteration_id"] = pd.to_numeric(
            df["iteration_id"].astype(str).str.extract(r"(\d+)", expand=False),
            errors="coerce"
        )
 
    return metrics, attacks, exposures
 
 
def bar_labels(ax, bars, fmt="{:.1f}", offset_frac=0.02):
    """Add value labels above each bar."""
    ylim_range = ax.get_ylim()[1] - ax.get_ylim()[0]
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + ylim_range * offset_frac,
            fmt.format(h),
            ha="center", va="bottom", fontsize=9, fontweight="bold"
        )
 
 
def legend_patches():
    return [
        mpatches.Patch(color=C_TRAD, label="Traditional VM"),
        mpatches.Patch(color=C_CTEM, label="CTEM"),
    ]
 
 
def save(fig, name):
    fig.savefig(PLOTS_DIR / name, dpi=300, bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    print(f"  saved → {PLOTS_DIR / name}")
 
 
#methodology metrics comparison
def plot_methodology_metrics(metrics):
    """6-panel comparison of all 5 success-criteria metrics + summary table."""
    plt.rcdefaults()
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle(
        "CTEM vs Traditional VM - Complete Metrics Comparison",
        fontsize=16, fontweight="bold", y=1.01
    )
 
    wf_order = ["Traditional VM", "CTEM"]
    df = metrics.set_index("workflow").reindex(wf_order)
 
    panels = [
        (axes[0, 0], "mew_hours",                 "SC1: Mean Exposure Window (MEW)\nLower is Better",   "Hours",         False, "{:.3f}h"),
        (axes[0, 1], "mttr_hours",                "SC3: Mean Time to Remediate (MTTR)\nLower is Better", "Hours",         False, "{:.3f}h"),
        (axes[0, 2], "cec_coverage_percent",       "SC2: Critical Exposure Coverage (CEC)\nHigher is Better", "Coverage (%)", True,  "{:.1f}%"),
        (axes[1, 0], "rfr_percent",                "SC2b: Remediation Focus Ratio (RFR)\nHigher is Better",  "Ratio (%)",    True,  "{:.1f}%"),
        (axes[1, 1], "attack_success_rate_percent","SC4: Attack Success Rate\nLower is Better",           "Rate (%)",      True,  "{:.1f}%"),
    ]
 
    for ax, col, title, ylabel, pct_ylim, fmt in panels:
        vals  = df[col].values
        bars  = ax.bar(wf_order, vals, color=COLORS, alpha=ALPHA,
                       edgecolor="black", linewidth=1.2, width=0.5)
        ax.set_title(title, fontweight="bold", fontsize=11)
        ax.set_ylabel(ylabel, fontsize=10)
        ax.grid(True, alpha=0.3, axis="y", linestyle="--")
        if pct_ylim:
            ax.set_ylim(0, 115)
        ax.tick_params(axis="x", labelsize=9)
        bar_labels(ax, bars, fmt=fmt)
 
    # Panel 6: clean summary table
    ax6 = axes[1, 2]
    ax6.axis("off")
    col_labels = ["Metric", "Trad. VM", "CTEM", "Δ"]
    rows = [
        ["MEW",  f"{df.loc['Traditional VM','mew_hours']:.3f}h",
                 f"{df.loc['CTEM','mew_hours']:.3f}h",
                 f"−{(1 - df.loc['CTEM','mew_hours']/df.loc['Traditional VM','mew_hours'])*100:.1f}%"],
        ["MTTR", f"{df.loc['Traditional VM','mttr_hours']:.3f}h",
                 f"{df.loc['CTEM','mttr_hours']:.3f}h",
                 f"−{(1 - df.loc['CTEM','mttr_hours']/df.loc['Traditional VM','mttr_hours'])*100:.1f}%"],
        ["CEC",  f"{df.loc['Traditional VM','cec_coverage_percent']:.1f}%",
                 f"{df.loc['CTEM','cec_coverage_percent']:.1f}%",
                 "="],
        ["RFR",  f"{df.loc['Traditional VM','rfr_percent']:.1f}%",
                 f"{df.loc['CTEM','rfr_percent']:.1f}%",
                 f"+{df.loc['CTEM','rfr_percent'] - df.loc['Traditional VM','rfr_percent']:.1f}pp"],
        ["Attack\nRate", f"{df.loc['Traditional VM','attack_success_rate_percent']:.1f}%",
                         f"{df.loc['CTEM','attack_success_rate_percent']:.1f}%",
                         "="],
    ]
    tbl = ax6.table(
        cellText=rows, colLabels=col_labels,
        cellLoc="center", loc="center",
        bbox=[0, 0.1, 1, 0.85]
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    for (r, c), cell in tbl.get_celld().items():
        cell.set_edgecolor("#CCCCCC")
        if r == 0:
            cell.set_facecolor("#2E75B6")
            cell.set_text_props(color="white", fontweight="bold")
        elif c == 3:  # Δ column
            val = cell.get_text().get_text()
            cell.set_facecolor("#E2EFDA" if val.startswith("+") or val == "="
                               else "#FCE4D6" if val.startswith("−") and "0.0" not in val
                               else "#FFFFFF")
        else:
            cell.set_facecolor("#F9F9F9" if r % 2 == 0 else "#FFFFFF")
 
    ax6.set_title("Summary", fontweight="bold", fontsize=11, pad=4)
    fig.legend(handles=legend_patches(), loc="upper right",
               framealpha=0.9, fontsize=10)
 
    save(fig, "methodology_metrics_comparison.png")
 
 
#ttack simulation analysis 
def plot_attack_simulations(attacks):
    """Attack success rate, path length, type distribution, and per-type success rates."""
    # FIX Bug 3: named agg instead of multi-level agg+rename
    wf_stats = attacks.groupby("workflow_type").agg(
        total_attempts   = ("success", "count"),
        successful_attacks = ("success", "sum"),
        avg_path_length  = ("steps_count", "mean"),
        path_length_std  = ("steps_count", "std"),
    ).round(3)
    wf_stats["success_rate_pct"] = (
        wf_stats["successful_attacks"] / wf_stats["total_attempts"] * 100
    ).round(2)
    wf_stats = wf_stats.reindex(["Traditional VM", "CTEM"])
 
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle("Attack Simulation Analysis - CTEM vs Traditional VM",
                 fontsize=16, fontweight="bold")
 
    wf_labels = wf_stats.index.tolist()
    wf_colors = [C_TRAD if w == "Traditional VM" else C_CTEM for w in wf_labels]
 
    # 1 - Success rate
    ax1 = axes[0, 0]
    bars = ax1.bar(wf_labels, wf_stats["success_rate_pct"],
                   color=wf_colors, alpha=ALPHA, edgecolor="black", linewidth=1.2, width=0.5)
    ax1.set_title("Attack Success Rate by Methodology", fontweight="bold")
    ax1.set_ylabel("Success Rate (%)")
    ax1.set_ylim(0, 115)
    ax1.grid(True, alpha=0.3, axis="y", linestyle="--")
    bar_labels(ax1, bars, fmt="{:.1f}%")
 
    # 2 - Average path length with error bars
    ax2 = axes[0, 1]
    bars = ax2.bar(wf_labels, wf_stats["avg_path_length"],
                   color=wf_colors, alpha=ALPHA, edgecolor="black", linewidth=1.2,
                   yerr=wf_stats["path_length_std"], capsize=6, width=0.5,
                   error_kw={"linewidth": 1.5, "ecolor": "black"})
    ax2.set_title("Average Attack Path Length (steps ± SD)", fontweight="bold")
    ax2.set_ylabel("Steps in Attack Path")
    ax2.grid(True, alpha=0.3, axis="y", linestyle="--")
    for bar, v, s in zip(bars, wf_stats["avg_path_length"], wf_stats["path_length_std"]):
        ax2.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + s + 0.08,
                 f"{v:.1f}±{s:.2f}",
                 ha="center", va="bottom", fontsize=9, fontweight="bold")
 
    # 3 - Attack type distribution (side-by-side grouped bars)
    ax3 = axes[1, 0]
    type_counts = (
        attacks.groupby(["workflow_type", "attack_type"])
        .size()
        .unstack("attack_type", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
    )
    x     = np.arange(len(type_counts.columns))
    width = 0.35
    ax3.bar(x - width/2, type_counts.loc["Traditional VM"], width,
            label="Traditional VM", color=C_TRAD, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax3.bar(x + width/2, type_counts.loc["CTEM"],           width,
            label="CTEM",           color=C_CTEM, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax3.set_xticks(x)
    ax3.set_xticklabels(type_counts.columns, rotation=25, ha="right", fontsize=9)
    ax3.set_title("Attack Type Distribution", fontweight="bold")
    ax3.set_ylabel("Number of Attempts")
    ax3.legend()
    ax3.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    # 4 - Success rate by attack type (grouped bars)
    ax4 = axes[1, 1]
    sr_by_type = (
        attacks.groupby(["workflow_type", "attack_type"])["success"]
        .mean()
        .mul(100)
        .round(1)
        .unstack("attack_type", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
    )
    x = np.arange(len(sr_by_type.columns))
    ax4.bar(x - width/2, sr_by_type.loc["Traditional VM"], width,
            label="Traditional VM", color=C_TRAD, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax4.bar(x + width/2, sr_by_type.loc["CTEM"],           width,
            label="CTEM",           color=C_CTEM, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax4.set_xticks(x)
    ax4.set_xticklabels(sr_by_type.columns, rotation=25, ha="right", fontsize=9)
    ax4.set_title("Success Rate by Attack Type", fontweight="bold")
    ax4.set_ylabel("Success Rate (%)")
    ax4.set_ylim(0, 115)
    ax4.legend()
    ax4.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    fig.legend(handles=legend_patches(), loc="upper right",
               framealpha=0.9, fontsize=10)
    save(fig, "attack_simulations_analysis.png")
 
 
#exposure timeline (MEW and MTTR per iteration)
def plot_exposure_timeline(exposures):
    """Line plots of MEW and MTTR averaged per iteration, per workflow."""
    # FIX Bug 4: iteration_id already cast to numeric in load_csvs()
    critical     = exposures[exposures["severity"] == "CRITICAL"].copy()
    high_or_crit = exposures[exposures["severity"].isin(["CRITICAL", "HIGH"])].copy()
 
    mew_iter  = (critical.groupby(["workflow_type", "iteration_id"])["mew_seconds"]
                 .mean().div(3600).reset_index()
                 .sort_values("iteration_id"))
    mttr_iter = (high_or_crit.groupby(["workflow_type", "iteration_id"])["mttr_seconds"]
                 .mean().div(3600).reset_index()
                 .sort_values("iteration_id"))
 
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle("Exposure Timeline - Performance Across Iterations",
                 fontsize=16, fontweight="bold")
 
    for ax, df, metric, title, ylabel in [
        (axes[0], mew_iter,  "mew_seconds",  "Mean Exposure Window (MEW) - CRITICAL Exposures",       "MEW (hours)"),
        (axes[1], mttr_iter, "mttr_seconds", "Mean Time to Remediate (MTTR) - CRITICAL + HIGH Exposures", "MTTR (hours)"),
    ]:
        for wf, color, marker in [("Traditional VM", C_TRAD, "o"), ("CTEM", C_CTEM, "s")]:
            grp = df[df["workflow_type"] == wf]
            if grp.empty:
                continue
            col = "mew_seconds" if "mew" in metric else "mttr_seconds"
            ax.plot(grp["iteration_id"], grp[col],
                    marker=marker, label=wf, color=color,
                    linewidth=2, markersize=5, alpha=0.85)
 
        ax.set_title(title, fontweight="bold", fontsize=11)
        ax.set_xlabel("Iteration number")
        ax.set_ylabel(ylabel)
        ax.legend()
        ax.grid(True, alpha=0.3, linestyle="--")
 
    save(fig, "exposure_timeline_analysis.png")
 
 
#success criteria dashboard 
def plot_success_criteria_dashboard(metrics, attacks, exposures):
    """One panel per success criterion + per-severity MEW breakdown."""
    wf_attack = attacks.groupby("workflow_type").agg(
        attack_success_rate = ("success", lambda x: x.mean() * 100),
        avg_path_length     = ("steps_count", "mean"),
    ).round(2).reindex(["Traditional VM", "CTEM"])
 
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle("CTEM Success Criteria Dashboard", fontsize=18, fontweight="bold", y=1.01)
 
    df = metrics.set_index("workflow").reindex(["Traditional VM", "CTEM"])
    wf_labels = ["Traditional VM", "CTEM"]
 
    def simple_bar(ax, values, title, ylabel, pct=False, lower_is_better=True, fmt="{:.2f}"):
        bars = ax.bar(wf_labels, values, color=COLORS, alpha=ALPHA,
                      edgecolor="black", linewidth=1.2, width=0.5)
        ax.set_title(title, fontweight="bold", fontsize=11)
        ax.set_ylabel(ylabel, fontsize=10)
        if pct:
            ax.set_ylim(0, 115)
        ax.grid(True, alpha=0.3, axis="y", linestyle="--")
        ax.tick_params(axis="x", labelsize=9)
        bar_labels(ax, bars, fmt=fmt)
        arrow = "↓ better" if lower_is_better else "↑ better"
        ax.text(0.98, 0.98, arrow, transform=ax.transAxes,
                ha="right", va="top", fontsize=8, color="gray")
        return bars
 
    # SC1 MEW
    simple_bar(axes[0,0], df["mew_hours"].values,
               "SC1: Mean Exposure Window (MEW)", "Hours", fmt="{:.3f}h", lower_is_better=True)
    # SC2 CEC
    simple_bar(axes[0,1], df["cec_coverage_percent"].values,
               "SC2: Critical Exposure Coverage (CEC)", "Coverage (%)", pct=True,
               fmt="{:.1f}%", lower_is_better=False)
    # SC3 MTTR
    simple_bar(axes[0,2], df["mttr_hours"].values,
               "SC3: Mean Time to Remediate (MTTR)", "Hours", fmt="{:.3f}h", lower_is_better=True)
    # SC4 attack success
    simple_bar(axes[1,0], wf_attack["attack_success_rate"].values,
               "SC4: Attack Success Rate", "Rate (%)", pct=True,
               fmt="{:.1f}%", lower_is_better=True)
    # RFR
    simple_bar(axes[1,1], df["rfr_percent"].values,
               "Remediation Focus Ratio (RFR)", "Ratio (%)", pct=True,
               fmt="{:.1f}%", lower_is_better=False)
 
    # Bonus panel: per-severity MEW breakdown (grouped bars)
    ax6 = axes[1,2]
    sev_mew = (
        exposures.groupby(["workflow_type", "severity"])["mew_seconds"]
        .mean().div(60).round(1)   # convert to minutes for readability
        .unstack("severity", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
        [["CRITICAL", "HIGH", "MEDIUM"]]
    )
    x = np.arange(3)
    w = 0.35
    ax6.bar(x - w/2, sev_mew.loc["Traditional VM"], w, label="Traditional VM",
            color=C_TRAD, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax6.bar(x + w/2, sev_mew.loc["CTEM"],           w, label="CTEM",
            color=C_CTEM, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax6.set_xticks(x)
    ax6.set_xticklabels(["CRITICAL", "HIGH", "MEDIUM"])
    ax6.set_title("MEW by Severity (minutes)\nLower is Better", fontweight="bold", fontsize=11)
    ax6.set_ylabel("MEW (minutes)")
    ax6.legend()
    ax6.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    fig.legend(handles=legend_patches(), loc="upper right",
               framealpha=0.9, fontsize=10)
    save(fig, "success_criteria_dashboard.png")
 
 
#exposure deep dive (severity + vulnerability type breakdown)
def plot_exposure_deep_dive(exposures):
    """Breakdown of exposures by severity, vulnerability type, service, and RFR detail."""
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle("Exposure Deep Dive - Severity, Vulnerability Types & Remediation Focus",
                 fontsize=15, fontweight="bold")
 
    # 1 - Severity distribution
    ax1 = axes[0, 0]
    sev_counts = (
        exposures.groupby(["workflow_type", "severity"]).size()
        .unstack("severity", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
        [["CRITICAL", "HIGH", "MEDIUM"]]
    )
    x = np.arange(3); w = 0.35
    ax1.bar(x - w/2, sev_counts.loc["Traditional VM"], w, label="Traditional VM",
            color=C_TRAD, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax1.bar(x + w/2, sev_counts.loc["CTEM"],           w, label="CTEM",
            color=C_CTEM, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax1.set_xticks(x)
    ax1.set_xticklabels(["CRITICAL", "HIGH", "MEDIUM"])
    ax1.set_title("Exposures by Severity", fontweight="bold")
    ax1.set_ylabel("Count")
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    # 2 - Vulnerability type distribution (horizontal bar)
    ax2 = axes[0, 1]
    vtype_counts = (
        exposures.groupby(["workflow_type", "vulnerability_type"]).size()
        .unstack("vulnerability_type", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
    )
    y = np.arange(len(vtype_counts.columns)); w2 = 0.35
    ax2.barh(y + w2/2, vtype_counts.loc["Traditional VM"], w2,
             label="Traditional VM", color=C_TRAD, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax2.barh(y - w2/2, vtype_counts.loc["CTEM"],           w2,
             label="CTEM",           color=C_CTEM, alpha=ALPHA, edgecolor="black", linewidth=0.8)
    ax2.set_yticks(y)
    ax2.set_yticklabels(vtype_counts.columns, fontsize=8)
    ax2.set_title("Vulnerability Type Distribution", fontweight="bold")
    ax2.set_xlabel("Count")
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis="x", linestyle="--")
 
    # 3 - on_attack_path vs off for each workflow (stacked bar)
    ax3 = axes[1, 0]
    path_counts = (
        exposures.groupby(["workflow_type", "on_attack_path"]).size()
        .unstack("on_attack_path", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
        .rename(columns={0: "Off attack path", 1: "On attack path"})
    )
    wf_labels = ["Traditional VM", "CTEM"]
    wf_colors_bar = [C_TRAD, C_CTEM]
    bottom_vals = np.zeros(2)
    bar_colors  = ["#CCCCCC", "#E24B4A"]
    for col, bc in zip(path_counts.columns, bar_colors):
        vals = path_counts[col].values
        bars = ax3.bar(wf_labels, vals, bottom=bottom_vals, color=bc,
                       alpha=ALPHA, edgecolor="black", linewidth=0.8, label=col, width=0.5)
        for bar, v, bot in zip(bars, vals, bottom_vals):
            if v > 20:
                ax3.text(bar.get_x() + bar.get_width() / 2,
                         bot + v / 2,
                         str(int(v)),
                         ha="center", va="center", fontsize=9, fontweight="bold", color="white")
        bottom_vals += vals
    ax3.set_title("Exposures On vs Off Attack Path\n(stacked - red = on attack path)", fontweight="bold")
    ax3.set_ylabel("Count")
    ax3.legend(loc="upper right")
    ax3.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    # 4 - RFR breakdown: remediated on-path vs off-path
    ax4 = axes[1, 1]
    rem = exposures[exposures["remediated"] == 1]
    rfr_detail = (
        rem.groupby(["workflow_type", "on_attack_path"]).size()
        .unstack("on_attack_path", fill_value=0)
        .reindex(["Traditional VM", "CTEM"])
        .rename(columns={0: "Remediated (off path)", 1: "Remediated (on path)"})
    )
    bottom_vals = np.zeros(2)
    rfr_colors  = ["#FFB347", "#4ECDC4"]
    for col, bc in zip(rfr_detail.columns, rfr_colors):
        vals = rfr_detail[col].values
        bars = ax4.bar(wf_labels, vals, bottom=bottom_vals, color=bc,
                       alpha=ALPHA, edgecolor="black", linewidth=0.8, label=col, width=0.5)
        for bar, v, bot in zip(bars, vals, bottom_vals):
            if v > 20:
                ax4.text(bar.get_x() + bar.get_width() / 2,
                         bot + v / 2,
                         str(int(v)),
                         ha="center", va="center", fontsize=9, fontweight="bold", color="white")
        bottom_vals += vals
 
    # Overlay RFR % annotation
    rfr_pcts = rem.groupby("workflow_type")["on_attack_path"].mean().mul(100).reindex(
        ["Traditional VM", "CTEM"])
    for i, (wf, pct) in enumerate(rfr_pcts.items()):
        total = rfr_detail.loc[wf].sum()
        ax4.text(i, total + 15, f"RFR: {pct:.1f}%",
                 ha="center", va="bottom", fontsize=10, fontweight="bold",
                 color=C_TRAD if wf == "Traditional VM" else C_CTEM)
 
    ax4.set_title("Remediation Focus Ratio Detail\n(teal = on attack path - higher is better)",
                  fontweight="bold")
    ax4.set_ylabel("Remediated Exposures")
    ax4.legend(loc="upper right")
    ax4.grid(True, alpha=0.3, axis="y", linestyle="--")
 
    save(fig, "exposure_deep_dive.png")
 
 
# main
def main():
    print("Loading CSVs...")
    metrics, attacks, exposures = load_csvs()
    print(f"  metrics:   {metrics.shape}  columns: {metrics.columns.tolist()}")
    print(f"  attacks:   {attacks.shape}  workflow_types: {attacks['workflow_type'].unique().tolist()}")
    print(f"  exposures: {exposures.shape}  severities: {exposures['severity'].unique().tolist()}")
 
    print("\nGenerating plots...")
    plot_methodology_metrics(metrics)
    plot_attack_simulations(attacks)
    plot_exposure_timeline(exposures)
    plot_success_criteria_dashboard(metrics, attacks, exposures)
    plot_exposure_deep_dive(exposures)
 
    print(f"\nAll 5 plots saved to: {PLOTS_DIR.resolve()}")
 
 
if __name__ == "__main__":
    main()