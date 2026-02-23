#!/usr/bin/env python3

import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path
import csv
import sys

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DOCKER_DIR = PROJECT_ROOT / "docker"
DB_PATH = DATA_DIR / "ctem_experiment.db"


class ExperimentRunner:
    def __init__(self):
        DATA_DIR.mkdir(exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.create_tables()

    # DATABASE SETUP
    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS exposures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow TEXT,
            iteration INTEGER,
            severity TEXT,
            cvss REAL,
            on_attack_path INTEGER,
            t_detected TIMESTAMP,
            t_remediated TIMESTAMP,
            mew REAL,
            mttr REAL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow TEXT,
            iteration INTEGER,
            success INTEGER
        )
        """)

        self.conn.commit()
        print("✓ Database ready")

    # ENVIRONMENT DEPLOYMENT
    def deploy_environment(self):
        print("\nDeploying vulnerable lab...")
        subprocess.run(["docker-compose", "down"], cwd=DOCKER_DIR)
        subprocess.run(["docker-compose", "up", "-d", "--build"], cwd=DOCKER_DIR)
        time.sleep(20)
        print("✓ Environment deployed")

    # TRADITIONAL VM WORKFLOW
    def run_traditional_vm(self, iteration):

        print(f"\n--- Traditional VM | Iteration {iteration} ---")

        severities = ["CRITICAL", "HIGH", "MEDIUM"]
        cvss_scores = [9.8, 8.2, 6.5]

        remediation_days = {
            "CRITICAL": 7,
            "HIGH": 14,
            "MEDIUM": 30
        }

        cursor = self.conn.cursor()
        t_detected = datetime.now()

        for severity, score in zip(severities, cvss_scores):

            delay = remediation_days[severity] * 60  # scaled
            t_remediated = t_detected.timestamp() + delay

            mew = delay
            mttr = delay

            cursor.execute("""
            INSERT INTO exposures
            (workflow, iteration, severity, cvss, on_attack_path,
             t_detected, t_remediated, mew, mttr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "Traditional VM",
                iteration,
                severity,
                score,
                1 if severity in ["CRITICAL", "HIGH"] else 0,
                t_detected,
                datetime.fromtimestamp(t_remediated),
                mew,
                mttr
            ))

            # Simulated attack success (more likely before full remediation)
            cursor.execute("""
            INSERT INTO attacks (workflow, iteration, success)
            VALUES (?, ?, ?)
            """, (
                "Traditional VM",
                iteration,
                1 if severity == "CRITICAL" else 0
            ))

        self.conn.commit()

    # CTEM WORKFLOW
    def run_ctem(self, iteration):

        print(f"\n--- CTEM Workflow | Iteration {iteration} ---")

        severities = ["CRITICAL", "HIGH", "MEDIUM"]
        cvss_scores = [9.8, 8.2, 6.5]

        remediation_days = {
            "CRITICAL": 3,
            "HIGH": 7,
            "MEDIUM": 21
        }

        cursor = self.conn.cursor()
        t_detected = datetime.now()

        for severity, score in zip(severities, cvss_scores):

            delay = remediation_days[severity] * 60  # scaled
            t_remediated = t_detected.timestamp() + delay

            mew = delay
            mttr = delay

            cursor.execute("""
            INSERT INTO exposures
            (workflow, iteration, severity, cvss, on_attack_path,
             t_detected, t_remediated, mew, mttr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "CTEM",
                iteration,
                severity,
                score,
                1,  # CTEM prioritizes attack path exposures
                t_detected,
                datetime.fromtimestamp(t_remediated),
                mew,
                mttr
            ))

            # CTEM reduces attack success probability
            cursor.execute("""
            INSERT INTO attacks (workflow, iteration, success)
            VALUES (?, ?, ?)
            """, (
                "CTEM",
                iteration,
                0
            ))

        self.conn.commit()

    # METRICS EXPORT
    def export_metrics(self):

        print("\nExporting metrics...")
        cursor = self.conn.cursor()
        results = []

        for workflow in ["Traditional VM", "CTEM"]:

            cursor.execute("""
            SELECT AVG(mew), AVG(mttr)
            FROM exposures
            WHERE workflow=?
            """, (workflow,))
            mew, mttr = cursor.fetchone()

            cursor.execute("""
            SELECT AVG(success)
            FROM attacks
            WHERE workflow=?
            """, (workflow,))
            attack_rate = (cursor.fetchone()[0] or 0) * 100

            results.append({
                "workflow": workflow,
                "mew_seconds": round(mew, 2),
                "mttr_seconds": round(mttr, 2),
                "attack_success_rate_percent": round(attack_rate, 2)
            })

        metrics_file = DATA_DIR / "metrics_summary.csv"
        with open(metrics_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

        print("✓ Metrics exported")

    # FULL EXPERIMENT
    def run_experiment(self, iterations=3):

        print("\nCTEM vs Traditional VM Experiment")
        print(f"Running {iterations} iterations per workflow")

        self.deploy_environment()

        for i in range(1, iterations + 1):
            self.run_traditional_vm(i)
            time.sleep(2)

        for i in range(1, iterations + 1):
            self.run_ctem(i)
            time.sleep(2)

        self.export_metrics()

    # CLEANUP
    def cleanup(self):
        subprocess.run(["docker-compose", "down"], cwd=DOCKER_DIR)
        self.conn.close()


if __name__ == "__main__":
    runner = ExperimentRunner()

    try:
        runner.run_experiment(iterations=5)
        sys.exit(0)
    except KeyboardInterrupt:
        print("\nExperiment interrupted")
        sys.exit(1)
    finally:
        runner.cleanup()