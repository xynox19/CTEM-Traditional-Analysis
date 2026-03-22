#!/usr/bin/env python3
from pathlib import Path

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError as imp_err:
    raise ImportError(
        "matplotlib is required to generate plots. Install it with `pip install -r requirements.txt`."
    ) from imp_err

import pandas as pd

from attack_surface_context import AttackSurfaceDiscoveryAnalyzer
from ctem_context import CTEMContextAnalyzer
from pentesting_context import PentestingContextAnalyzer
from vulnerability_scanner import VulnerabilityScanner
from vm_scanning_context import VMScanningContextAnalyzer


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PLOTS_DIR = DATA_DIR / "plots"


def gather_context_metrics():
    scanner = VulnerabilityScanner()
    vulns = scanner.scan_targets([
        'http://localhost:8080',
        'localhost:3306',
        'http://localhost:3000'
    ])

    # Attack Surface Discovery
    asd = AttackSurfaceDiscoveryAnalyzer()
    asd_assets = asd.discover_assets(vulns)
    asd_paths = asd.analyze_exposure_paths(asd_assets)
    asd_prioritized = asd.prioritize_by_exposure_criticality(asd_paths)
    asd_metrics = asd.calculate_metrics(asd_prioritized)

    # Pentesting context
    pent = PentestingContextAnalyzer()
    pent_scoped = pent.add_scope_context(vulns)
    pent_prioritized = pent.prioritize_by_exploitability(pent_scoped)
    pent_exploited = pent.simulate_exploitation(pent_prioritized)
    pent_metrics = pent.calculate_metrics(pent_exploited)

    # CTEM context
    ctem = CTEMContextAnalyzer()
    ctem_contextualized = ctem.add_business_context(vulns)
    ctem_prioritized = ctem.prioritize_by_risk(ctem_contextualized)
    ctem_validated = ctem.validate_exploitability(ctem_prioritized)
    ctem_metrics = ctem.calculate_metrics(ctem_validated)

    # VM scanning context
    vm = VMScanningContextAnalyzer()
    vm_scanned = vm.schedule_and_execute_scan(vulns)
    vm_prioritized = vm.apply_cvss_prioritization(vm_scanned)
    vm_tickets = vm.create_remediation_tickets(vm_prioritized)
    vm_metrics = vm.calculate_metrics(vm_scanned, vm_tickets)

    return [asd_metrics, pent_metrics, ctem_metrics, vm_metrics]


def plot_metrics_table(metrics_list):
    df = pd.DataFrame(metrics_list).set_index('context')

    # Normalize missing values to 0 for plotting clarity
    df = df.fillna(0)

    # Ensure plots directory exists
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    # Plot primary comparison metrics
    primary_metrics = ['total_vulnerabilities', 'critical', 'high', 'avg_cvss', 'avg_exposure_criticality', 'avg_risk_score']
    primary_metrics = [m for m in primary_metrics if m in df.columns]
    df[primary_metrics].plot(kind='bar', figsize=(10, 6), title='Context Comparison: Vulnerabilities, Severity & Risk')
    plt.ylabel('Count / Score')
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / 'context_vulnerability_comparison.png')
    plt.close('all')

    # Plot exploitation-focused metrics (where available)
    exploitation_metrics = [k for k in df.columns if k in ('exploited', 'exploitable', 'avg_exploit_priority', 'avg_exploit_probability')]
    if exploitation_metrics:
        df[exploitation_metrics].plot(kind='bar', figsize=(10, 5), title='Context Comparison: Exploitation Metrics')
        plt.ylabel('Count / Score')
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / 'context_exploitation_comparison.png')
        plt.close('all')

    # Plot scanning/coverage metrics
    scan_metrics = [k for k in df.columns if k in ('avg_detection_confidence', 'tickets_created', 'open_tickets', 'external_exposure', 'internal_exposure')]
    if scan_metrics:
        df[scan_metrics].plot(kind='bar', figsize=(10, 6), title='Context Comparison: Scanning & Exposure Metrics')
        plt.ylabel('Count / Score')
        plt.tight_layout()
        plt.savefig(PLOTS_DIR / 'context_scanning_comparison.png')
        plt.close('all')

    print("\n📋 Context metrics table:")
    print(df)
    print(f"\n✅ Plots saved to: {PLOTS_DIR.resolve()}")


def main():
    metrics = gather_context_metrics()
    plot_metrics_table(metrics)


if __name__ == '__main__':
    main()
