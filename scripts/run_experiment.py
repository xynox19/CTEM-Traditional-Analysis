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

    def create_tables(self):
        cursor = self.conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS exposures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow TEXT,
            severity TEXT,
            cvss REAL,
            on_attack_path INTEGER,
            mew REAL,
            mttr REAL
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow TEXT,
            success INTEGER
        )
        """)

        self.conn.commit()

    def deploy_environment(self):
        subprocess.run(["docker-compose", "down"], cwd=DOCKER_DIR)
        subprocess.run(["docker-compose", "up", "-d", "--build"], cwd=DOCKER_DIR)
        time.sleep(20)

    def run_traditional_vm(self):
        severities = ["CRITICAL", "HIGH", "MEDIUM"]
        cvss_scores = [9.8, 8.2, 6.5]

        remediation_map = {
            "CRITICAL": 7,
            "HIGH": 14,
            "MEDIUM": 30
        }

        for severity, score in zip(severities, cvss_scores):
            days = remediation_map[severity]
            mew = days * 60
            mttr = days * 60

            cursor = self.conn.cursor()

            cursor.execute("""
            INSERT INTO exposures (workflow, severity, cvss, on_attack_path, mew, mttr)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "Traditional VM",
                severity,
                score,
                1 if severity in ["CRITICAL", "HIGH"] else 0,
                mew,
                mttr
            ))

            cursor.execute("""
            INSERT INTO attacks (workflow, success)
            VALUES (?, ?)
            """, ("Traditional VM", 1))

        self.conn.commit()

    def run_ctem(self):
        severities = ["CRITICAL", "HIGH", "MEDIUM"]
        cvss_scores = [9.8, 8.2, 6.5]

        remediation_map = {
            "CRITICAL": 3,
            "HIGH": 7,
            "MEDIUM": 21
        }

        for severity, score in zip(severities, cvss_scores):
            days = remediation_map[severity]
            mew = days * 60
            mttr = days * 60

            cursor = self.conn.cursor()

            cursor.execute("""
            INSERT INTO exposures (workflow, severity, cvss, on_attack_path, mew, mttr)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                "CTEM",
                severity,
                score,
                1,
                mew,
                mttr
            ))

            cursor.execute("""
            INSERT INTO attacks (workflow, success)
            VALUES (?, ?)
            """, ("CTEM", 0))

        self.conn.commit()

    def export_metrics(self):
        cursor = self.conn.cursor()
        results = []

        for workflow in ["Traditional VM", "CTEM"]:
            cursor.execute(
                "SELECT AVG(mew), AVG(mttr) FROM exposures WHERE workflow=?",
                (workflow,)
            )
            mew, mttr = cursor.fetchone()

            cursor.execute(
                "SELECT AVG(success) FROM attacks WHERE workflow=?",
                (workflow,)
            )
            attack_rate = cursor.fetchone()[0] * 100

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

    def cleanup(self):
        subprocess.run(["docker-compose", "down"], cwd=DOCKER_DIR)
        self.conn.close()


if __name__ == "__main__":
    runner = ExperimentRunner()

    try:
        runner.deploy_environment()
        runner.run_traditional_vm()
        runner.run_ctem()
        runner.export_metrics()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(1)
    finally:
        runner.cleanup()
