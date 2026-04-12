#!/usr/bin/env python3
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import pandas as pd
import numpy as np

DATA_DIR  = Path(__file__).resolve().parent.parent / "data"
PLOTS_DIR = DATA_DIR / "plots"
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

C_TRAD  = "#26215F"
C_CTEM  = "#90D541"
COLORS  = [C_TRAD, C_CTEM]
ALPHA   = 0.85


def load_csvs():
    metrics   = pd.read_csv(DATA_DIR / "metrics_summary.csv")
    attacks   = pd.read_csv(DATA_DIR / "attack_simulations.csv")
    exposures = pd.read_csv(DATA_DIR / "exposures.csv")

    for df in [metrics, attacks, exposures]:
        df.columns = df.columns.str.strip()

    metrics["workflow"]        = metrics["workflow"].str.strip()
    attacks["workflow_type"]   = attacks["workflow_type"].str.strip()
    exposures["workflow_type"] = exposures["workflow_type"].str.strip()
    exposures["severity"]      = exposures["severity"].str.strip()

    for df in [attacks, exposures]:
        df["iteration_id"] = pd.to_numeric(
            df["iteration_id"].astype(str).str.extract(r"(\d+)", expand=False),
            errors="coerce"
        )

    return metrics, attacks, exposures


def bar_labels(ax, bars, fmt="{:.1f}", offset_frac=0.02):
    ylim_range = ax.get_ylim()[1] - ax.get_ylim()[0]
    for bar in bars:
        h = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            h + ylim_range * offset_frac,
            fmt.format(h),
            ha="center",
            va="bottom",
            fontsize=9,
            fontweight="bold"
        )


def legend_patches():
    return [
        mpatches.Patch(color=C_TRAD, label="Traditional VM"),
        mpatches.Patch(color=C_CTEM, label="CTEM"),
    ]


def save(fig, name):
    fig.savefig(PLOTS_DIR / name, dpi=300, bbox_inches="tight", pad_inches=0.3)
    plt.close(fig)
    print(f"saved → {name}")


def plot_methodology_metrics(metrics):
    plt.rcdefaults()
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))

    wf_order = ["Traditional VM", "CTEM"]
    df = metrics.set_index("workflow").reindex(wf_order)

    panels = [
        (axes[0,0],"mew_hours","MEW","Hours",False,"{:.3f}h"),
        (axes[0,1],"mttr_hours","MTTR","Hours",False,"{:.3f}h"),
        (axes[0,2],"cec_coverage_percent","CEC","Coverage (%)",True,"{:.1f}%"),
        (axes[1,0],"rfr_percent","RFR","Ratio (%)",True,"{:.1f}%"),
        (axes[1,1],"attack_success_rate_percent","Attack Success Rate","Rate (%)",True,"{:.1f}%"),
    ]

    for ax,col,title,ylabel,pct_ylim,fmt in panels:
        vals=df[col].values
        bars=ax.bar(wf_order,vals,color=COLORS,alpha=ALPHA,
                    edgecolor="black",linewidth=1.2,width=0.5)
        ax.set_title(title,fontweight="bold")
        ax.set_ylabel(ylabel)
        ax.grid(True,alpha=0.3,axis="y",linestyle="--")
        if pct_ylim:
            ax.set_ylim(0,115)
        bar_labels(ax,bars,fmt=fmt)

    axes[1,2].axis("off")

    fig.legend(handles=legend_patches(),loc="upper right")
    save(fig,"methodology_metrics_comparison.png")


def plot_attack_simulations(attacks):
    wf_stats = attacks.groupby("workflow_type").agg(
        total_attempts=("success","count"),
        successful_attacks=("success","sum"),
        avg_path_length=("steps_count","mean"),
        path_length_std=("steps_count","std"),
    ).round(3)

    wf_stats["success_rate_pct"] = (
        wf_stats["successful_attacks"] /
        wf_stats["total_attempts"] * 100
    ).round(2)

    wf_stats = wf_stats.reindex(["Traditional VM","CTEM"])

    fig, axes = plt.subplots(1,2,figsize=(12,5))

    labels = wf_stats.index.tolist()
    colors = [C_TRAD if w=="Traditional VM" else C_CTEM for w in labels]

    bars=axes[0].bar(labels,wf_stats["success_rate_pct"],
                     color=colors,alpha=ALPHA,
                     edgecolor="black",linewidth=1.2)
    axes[0].set_ylabel("Success Rate (%)")
    axes[0].set_ylim(0,115)
    axes[0].grid(True,alpha=0.3,axis="y",linestyle="--")
    bar_labels(axes[0],bars,fmt="{:.1f}%")

    bars=axes[1].bar(labels,wf_stats["avg_path_length"],
                     color=colors,alpha=ALPHA,
                     edgecolor="black",linewidth=1.2,
                     yerr=wf_stats["path_length_std"],capsize=6)
    axes[1].set_ylabel("Steps")
    axes[1].grid(True,alpha=0.3,axis="y",linestyle="--")

    save(fig,"attack_simulations_analysis.png")


def plot_exposure_timeline(exposures):
    critical=exposures[exposures["severity"]=="CRITICAL"]
    high_or_crit=exposures[exposures["severity"].isin(["CRITICAL","HIGH"])]

    mew_iter=(critical.groupby(["workflow_type","iteration_id"])["mew_seconds"]
              .mean().div(3600).reset_index())
    mttr_iter=(high_or_crit.groupby(["workflow_type","iteration_id"])["mttr_seconds"]
               .mean().div(3600).reset_index())

    fig,axes=plt.subplots(1,2,figsize=(14,5))

    for ax,df,col,label in [
        (axes[0],mew_iter,"mew_seconds","MEW (hours)"),
        (axes[1],mttr_iter,"mttr_seconds","MTTR (hours)")
    ]:
        for wf,color,marker in [
            ("Traditional VM",C_TRAD,"o"),
            ("CTEM",C_CTEM,"s")
        ]:
            grp=df[df["workflow_type"]==wf]
            ax.plot(grp["iteration_id"],grp[col],
                    marker=marker,color=color,label=wf,linewidth=2)
        ax.set_xlabel("Iteration")
        ax.set_ylabel(label)
        ax.grid(True,alpha=0.3,linestyle="--")
        ax.legend()

    save(fig,"exposure_timeline_analysis.png")


def plot_monte_carlo_distribution(exposures):
    critical=exposures[exposures["severity"]=="CRITICAL"]

    fig,ax=plt.subplots(figsize=(8,6))

    for wf,color in [
        ("Traditional VM",C_TRAD),
        ("CTEM",C_CTEM)
    ]:
        data=critical[critical["workflow_type"]==wf]["mew_seconds"]/3600
        ax.hist(data,bins=30,alpha=0.6,label=wf,color=color)

    ax.set_xlabel("MEW (hours)")
    ax.set_ylabel("Frequency")
    ax.legend()
    ax.grid(True,alpha=0.3,linestyle="--")

    save(fig,"monte_carlo_mew_distribution.png")


def plot_success_criteria_dashboard(metrics,attacks,exposures):
    fig,axes=plt.subplots(1,3,figsize=(15,5))

    df=metrics.set_index("workflow").reindex(["Traditional VM","CTEM"])

    bars=axes[0].bar(df.index,df["mew_hours"],
                     color=COLORS,alpha=ALPHA,
                     edgecolor="black",linewidth=1.2)
    axes[0].set_title("MEW")
    bar_labels(axes[0],bars,"{:.3f}h")

    bars=axes[1].bar(df.index,df["mttr_hours"],
                     color=COLORS,alpha=ALPHA,
                     edgecolor="black",linewidth=1.2)
    axes[1].set_title("MTTR")
    bar_labels(axes[1],bars,"{:.3f}h")

    bars=axes[2].bar(df.index,df["cec_coverage_percent"],
                     color=COLORS,alpha=ALPHA,
                     edgecolor="black",linewidth=1.2)
    axes[2].set_title("CEC")
    axes[2].set_ylim(0,115)
    bar_labels(axes[2],bars,"{:.1f}%")

    save(fig,"success_criteria_dashboard.png")


def plot_exposure_deep_dive(exposures):
    fig,ax=plt.subplots(figsize=(8,6))

    sev_counts=(exposures.groupby(["workflow_type","severity"])
                .size().unstack(fill_value=0)
                .reindex(["Traditional VM","CTEM"]))

    sev_counts.plot(kind="bar",ax=ax,
                    color=[C_TRAD,C_CTEM,C_TRAD],
                    edgecolor="black")

    ax.set_ylabel("Count")
    ax.grid(True,alpha=0.3,axis="y",linestyle="--")

    save(fig,"exposure_deep_dive.png")


def main():
    print("Loading CSVs...")
    metrics,attacks,exposures=load_csvs()
    print(exposures.groupby("workflow_type")["iteration_id"].nunique())
    plot_methodology_metrics(metrics)
    plot_attack_simulations(attacks)
    plot_exposure_timeline(exposures)
    plot_monte_carlo_distribution(exposures)
    plot_success_criteria_dashboard(metrics,attacks,exposures)
    plot_exposure_deep_dive(exposures)

    print(f"All plots saved → {PLOTS_DIR.resolve()}")


if __name__=="__main__":
    main()