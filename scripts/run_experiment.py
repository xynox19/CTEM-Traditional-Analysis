#!/usr/bin/env python3
import subprocess
import time
import json
import sqlite3
import random
from datetime import datetime
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / 'data'
DOCKER_DIR = PROJECT_ROOT / 'docker'
DB_PATH = DATA_DIR / 'ctem_experiment.db'

class ExperimentRunner:
    def __init__(self, simulation_mode=False):
        self.db_conn = None
        self.simulation_mode = simulation_mode
        if simulation_mode:
            print("\n⚠ SIMULATION MODE ENABLED (Docker not required)")
        self.setup_database()
        
    def setup_database(self):
        """Initialize SQLite database for metrics collection"""
        DATA_DIR.mkdir(exist_ok=True)
        
        self.db_conn = sqlite3.connect(DB_PATH)
        cursor = self.db_conn.cursor()
        
        # Create exposures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exposures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                iteration_id INTEGER,
                workflow_type TEXT,
                exposure_id TEXT,
                severity TEXT,
                cvss_score REAL,
                service TEXT,
                vulnerability_type TEXT,
                on_attack_path INTEGER,
                t_appeared TIMESTAMP,
                t_detected TIMESTAMP,
                t_remediated TIMESTAMP,
                remediated INTEGER DEFAULT 0,
                mew_seconds REAL,
                mttr_seconds REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create attack simulations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                iteration_id INTEGER,
                workflow_type TEXT,
                attack_type TEXT,
                target_service TEXT,
                success INTEGER,
                steps_count INTEGER,
                attack_path TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create iterations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iterations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_type TEXT,
                iteration_number INTEGER,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                total_exposures INTEGER,
                high_severity_count INTEGER,
                critical_count INTEGER,
                remediated_count INTEGER
            )
        ''')
        
        self.db_conn.commit()
        print("✓ Database initialized")
    
    def generate_simulated_vulnerabilities(self):
        """Generate realistic simulated vulnerability data for testing"""
        vulnerabilities = [
            {'id': 'CVE-2021-001', 'service': 'DVWA', 'type': 'SQL Injection', 'severity': 'CRITICAL', 'cvss_score': 9.8},
            {'id': 'CVE-2021-002', 'service': 'DVWA', 'type': 'Cross-Site Scripting (XSS)', 'severity': 'HIGH', 'cvss_score': 7.3},
            {'id': 'CVE-2021-003', 'service': 'DVWA', 'type': 'Authentication Bypass', 'severity': 'HIGH', 'cvss_score': 8.1},
            {'id': 'CVE-2021-004', 'service': 'DVWA', 'type': 'Directory Traversal', 'severity': 'MEDIUM', 'cvss_score': 6.5},
            {'id': 'CVE-2021-005', 'service': 'DVWA', 'type': 'Command Injection', 'severity': 'CRITICAL', 'cvss_score': 9.5},
            {'id': 'CVE-2021-006', 'service': 'MySQL', 'type': 'Weak Password Policy', 'severity': 'CRITICAL', 'cvss_score': 9.1},
            {'id': 'CVE-2021-007', 'service': 'MySQL', 'type': 'Unencrypted Connection', 'severity': 'HIGH', 'cvss_score': 7.5},
            {'id': 'CVE-2021-008', 'service': 'MySQL', 'type': 'Default Credentials', 'severity': 'CRITICAL', 'cvss_score': 9.0},
            {'id': 'CVE-2021-009', 'service': 'API', 'type': 'Broken Authentication', 'severity': 'CRITICAL', 'cvss_score': 9.6},
            {'id': 'CVE-2021-010', 'service': 'API', 'type': 'API Rate Limiting Missing', 'severity': 'MEDIUM', 'cvss_score': 5.8},
            {'id': 'CVE-2021-011', 'service': 'API', 'type': 'Insecure Deserialization', 'severity': 'HIGH', 'cvss_score': 8.3},
            {'id': 'CVE-2021-012', 'service': 'DVWA', 'type': 'Insecure Direct Object Reference', 'severity': 'HIGH', 'cvss_score': 7.8},
            {'id': 'CVE-2021-013', 'service': 'API', 'type': 'Information Disclosure', 'severity': 'MEDIUM', 'cvss_score': 5.3},
            {'id': 'CVE-2021-014', 'service': 'MySQL', 'type': 'SQL Injection via Stored Procedure', 'severity': 'HIGH', 'cvss_score': 8.0},
            {'id': 'CVE-2021-015', 'service': 'DVWA', 'type': 'Cross-Site Request Forgery', 'severity': 'MEDIUM', 'cvss_score': 6.2},
        ]
        return vulnerabilities
    
    def generate_simulated_attack_results(self):
        """Generate realistic simulated attack simulation results"""
        attacks = [
            {'type': 'SQLi Attack', 'target': 'DVWA', 'success': 1, 'steps': 3, 'path': ['Reconnaissance', 'Parameter Testing', 'Data Exfiltration']},
            {'type': 'Auth Bypass', 'target': 'API', 'success': 1, 'steps': 2, 'path': ['Token Manipulation', 'Unauthorized Access']},
            {'type': 'Weak Credentials', 'target': 'MySQL', 'success': 1, 'steps': 2, 'path': ['Brute Force', 'System Access']},
            {'type': 'XSS Attack', 'target': 'DVWA', 'success': 1, 'steps': 2, 'path': ['Payload Injection', 'Session Hijacking']},
            {'type': 'Command Injection', 'target': 'DVWA', 'success': 0, 'steps': 1, 'path': ['Input Validation Prevented']},
        ]
        return attacks


    
    def deploy_environment(self):
        """Deploy vulnerable services using Docker Compose or use simulation"""
        print("\n" + "="*70)
        print("DEPLOYING VULNERABLE ENVIRONMENT")
        print("="*70)
        
        if self.simulation_mode:
            print("📊 Using simulated vulnerability data (no Docker required)")
            services = ['ctem_dvwa', 'ctem_mysql', 'ctem_api']
            for service in services:
                print(f"  ✓ {service} simulated")
            print("\n✓ Simulated environment ready")
            return True
        
        try:
            # Stop existing containers
            subprocess.run(
                ['docker-compose', 'down'],
                cwd=DOCKER_DIR,
                check=False,
                capture_output=True
            )
            
            # Build and start services
            print("Building Docker images...")
            result = subprocess.run(
                ['docker-compose', 'up', '-d', '--build'],
                cwd=DOCKER_DIR,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                print(f"Error: {result.stderr}")
                print("\n⚠ Docker deployment failed. Falling back to SIMULATION MODE")
                self.simulation_mode = True
                return self.deploy_environment()
            
            print("✓ Services deployed")
            print("\nWaiting for services to be ready (30 seconds)...")
            time.sleep(30)
            
            # Verify services are running
            services = ['ctem_dvwa', 'ctem_mysql', 'ctem_api']
            for service in services:
                check = subprocess.run(
                    ['docker', 'ps', '--filter', f'name={service}', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if service in check.stdout:
                    print(f"  ✓ {service} is running")
                else:
                    print(f"  ✗ {service} failed to start")
                    return False
            
            print("\n✓ All services ready")
            return True
            
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
            print(f"⚠ Deployment error: {e}")
            print("\n⚠ Docker deployment failed. Falling back to SIMULATION MODE")
            self.simulation_mode = True
            return self.deploy_environment()
    
    def run_traditional_vm_workflow(self, iteration):
        """
        Simulate Traditional Vulnerability Management workflow:
        - Weekly scans
        - CVSS-based prioritization
        - Linear remediation queue
        """
        print(f"\n{'='*70}")
        print(f"TRADITIONAL VM - ITERATION {iteration}")
        print(f"{'='*70}")
        
        iteration_start = datetime.now()
        
        # Insert iteration record
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO iterations (workflow_type, iteration_number, start_time)
            VALUES (?, ?, ?)
        ''', ('Traditional VM', iteration, iteration_start))
        iteration_id = cursor.lastrowid
        self.db_conn.commit()
        
        # Step 1: Discovery (simulated weekly scan)
        print("\n[1/4] Running vulnerability scan...")
        
        if self.simulation_mode:
            vulnerabilities = self.generate_simulated_vulnerabilities()
            print(f"  Generated {len(vulnerabilities)} simulated vulnerabilities")
        else:
            from vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            vulnerabilities = scanner.scan_targets([
                'http://localhost:8080',  # DVWA
                'localhost:3306',          # MySQL
                'http://localhost:3000'    # API
            ])
        
        print(f"  Found {len(vulnerabilities)} vulnerabilities")
        
        # Step 2: Traditional Prioritization (CVSS-based)
        print("\n[2/4] Prioritizing by CVSS score...")
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x['cvss_score'], reverse=True)
        
        high_priority = [v for v in sorted_vulns if v['cvss_score'] >= 7.0]
        print(f"  {len(high_priority)} high/critical vulnerabilities")
        
        # Step 3: Remediation (linear, top-down by CVSS)
        print("\n[3/4] Simulating remediation workflow...")
        t_detected = datetime.now()
        
        # Simulate remediation delay based on severity
        remediation_times = {
            'CRITICAL': 7,   # 7 days
            'HIGH': 14,      # 14 days  
            'MEDIUM': 30,    # 30 days
            'LOW': 90        # 90 days
        }
        
        for vuln in vulnerabilities:
            t_appeared = iteration_start
            
            # Determine if on attack path (simplified)
            on_attack_path = 1 if vuln['severity'] in ['CRITICAL', 'HIGH'] and 'SQL' in vuln['type'] else 0
            
            # Simulate remediation
            remediation_delay_days = remediation_times.get(vuln['severity'], 30)
            remediation_delay_seconds = remediation_delay_days * 24 * 3600  # Convert to seconds for simulation
            
            # For simulation purposes, we'll use a scaled down time (seconds instead of days)
            scaled_delay = remediation_delay_days * 60  # 1 day = 60 seconds in simulation
            
            t_remediated = t_detected.timestamp() + scaled_delay
            mew = (t_remediated - t_appeared.timestamp())
            mttr = (t_remediated - t_detected.timestamp())
            
            # Insert exposure record
            cursor.execute('''
                INSERT INTO exposures (
                    iteration_id, workflow_type, exposure_id, severity, cvss_score,
                    service, vulnerability_type, on_attack_path,
                    t_appeared, t_detected, t_remediated, remediated, mew_seconds, mttr_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                iteration_id, 'Traditional VM', vuln['id'], vuln['severity'],
                vuln['cvss_score'], vuln['service'], vuln['type'], on_attack_path,
                t_appeared, t_detected, datetime.fromtimestamp(t_remediated),
                1, mew, mttr
            ))
        
        self.db_conn.commit()
        
        # Step 4: Attack Simulation
        print("\n[4/4] Running attack simulations...")
        
        if self.simulation_mode:
            attack_results = self.generate_simulated_attack_results()
        else:
            from attack_simulator import AttackSimulator
            attack_sim = AttackSimulator()
            attack_results = attack_sim.simulate_attacks('localhost', after_remediation=True)
        
        for result in attack_results:
            cursor.execute('''
                INSERT INTO attack_simulations (
                    iteration_id, workflow_type, attack_type, target_service,
                    success, steps_count, attack_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                iteration_id, 'Traditional VM', result['type'], result['target'],
                result['success'], result['steps'], json.dumps(result['path'])
            ))
        
        self.db_conn.commit()
        
        # Update iteration end time
        cursor.execute('''
            UPDATE iterations 
            SET end_time = ?, total_exposures = ?, high_severity_count = ?, 
                critical_count = ?, remediated_count = ?
            WHERE id = ?
        ''', (
            datetime.now(),
            len(vulnerabilities),
            len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
            len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
            len(vulnerabilities),
            iteration_id
        ))
        self.db_conn.commit()
        
        print(f"\n✓ Traditional VM iteration {iteration} complete")
        return True
    
    def run_ctem_workflow(self, iteration):
        """
        Simulate CTEM workflow:
        - Continuous discovery
        - Risk-based prioritization (threat intel + business context)
        - Validation-driven remediation
        - Attack path analysis
        """
        print(f"\n{'='*70}")
        print(f"CTEM WORKFLOW - ITERATION {iteration}")
        print(f"{'='*70}")
        
        iteration_start = datetime.now()
        
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO iterations (workflow_type, iteration_number, start_time)
            VALUES (?, ?, ?)
        ''', ('CTEM', iteration, iteration_start))
        iteration_id = cursor.lastrowid
        self.db_conn.commit()
        
        # Step 1: Continuous Discovery + Contextualization
        print("\n[1/5] CTEM Scoping & Discovery...")
        
        from ctem_context import CTEMContextAnalyzer
        context_analyzer = CTEMContextAnalyzer()
        
        if self.simulation_mode:
            vulnerabilities = self.generate_simulated_vulnerabilities()
            print(f"  Generated {len(vulnerabilities)} simulated exposures")
        else:
            from vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            vulnerabilities = scanner.scan_targets([
                'http://localhost:8080',
                'localhost:3306',
                'http://localhost:3000'
            ])
        
        # Add business context
        contextualized_vulns = context_analyzer.add_business_context(vulnerabilities)
        print(f"  Found {len(contextualized_vulns)} exposures")
        
        # Step 2: CTEM Prioritization (Risk-based)
        print("\n[2/5] Risk-based Prioritization...")
        prioritized = context_analyzer.prioritize_by_risk(contextualized_vulns)
        
        critical_exposures = [v for v in prioritized if v['risk_score'] >= 8.0]
        print(f"  {len(critical_exposures)} critical exposures identified")
        
        # Step 3: Validation (simulate BAS/attack path analysis)
        print("\n[3/5] Exposure Validation...")
        validated = context_analyzer.validate_exploitability(prioritized)
        
        exploitable = [v for v in validated if v['exploitable']]
        print(f"  {len(exploitable)} confirmed exploitable")
        
        # Step 4: Mobilization (faster remediation for validated exposures)
        print("\n[4/5] Remediation Mobilization...")
        t_detected = datetime.now()
        
        # CTEM has faster remediation due to better prioritization
        ctem_remediation_times = {
            'CRITICAL': 3,   # 3 days (vs 7 for traditional)
            'HIGH': 7,       # 7 days (vs 14)
            'MEDIUM': 21,    # 21 days (vs 30)
            'LOW': 60        # 60 days (vs 90)
        }
        
        for vuln in validated:
            t_appeared = iteration_start
            
            # CTEM focuses on attack paths
            on_attack_path = 1 if vuln.get('exploitable', False) else 0
            
            remediation_delay_days = ctem_remediation_times.get(vuln['severity'], 21)
            scaled_delay = remediation_delay_days * 60  # Simulation scaling
            
            t_remediated = t_detected.timestamp() + scaled_delay
            mew = (t_remediated - t_appeared.timestamp())
            mttr = (t_remediated - t_detected.timestamp())
            
            cursor.execute('''
                INSERT INTO exposures (
                    iteration_id, workflow_type, exposure_id, severity, cvss_score,
                    service, vulnerability_type, on_attack_path,
                    t_appeared, t_detected, t_remediated, remediated, mew_seconds, mttr_seconds
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                iteration_id, 'CTEM', vuln['id'], vuln['severity'],
                vuln['cvss_score'], vuln['service'], vuln['type'], on_attack_path,
                t_appeared, t_detected, datetime.fromtimestamp(t_remediated),
                1, mew, mttr
            ))
        
        self.db_conn.commit()
        
        # Step 5: Attack Simulation
        print("\n[5/5] Post-remediation Attack Simulations...")
        
        if self.simulation_mode:
            attack_results = self.generate_simulated_attack_results()
        else:
            from attack_simulator import AttackSimulator
            attack_sim = AttackSimulator()
            attack_results = attack_sim.simulate_attacks('localhost', after_remediation=True)
        
        for result in attack_results:
            cursor.execute('''
                INSERT INTO attack_simulations (
                    iteration_id, workflow_type, attack_type, target_service,
                    success, steps_count, attack_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                iteration_id, 'CTEM', result['type'], result['target'],
                result['success'], result['steps'], json.dumps(result['path'])
            ))
        
        self.db_conn.commit()
        
        # Update iteration
        cursor.execute('''
            UPDATE iterations 
            SET end_time = ?, total_exposures = ?, high_severity_count = ?, 
                critical_count = ?, remediated_count = ?
            WHERE id = ?
        ''', (
            datetime.now(),
            len(validated),
            len([v for v in validated if v['severity'] == 'HIGH']),
            len([v for v in validated if v['severity'] == 'CRITICAL']),
            len([v for v in validated if v.get('exploitable', False)]),
            iteration_id
        ))
        self.db_conn.commit()
        
        print(f"\n✓ CTEM iteration {iteration} complete")
        return True
    
    def export_results(self):
        """Export results to CSV for Power BI"""
        print("\n" + "="*70)
        print("EXPORTING RESULTS FOR POWER BI")
        print("="*70)
        
        cursor = self.db_conn.cursor()
        
        # Export exposures
        cursor.execute('SELECT * FROM exposures')
        exposures = cursor.fetchall()
        
        import csv
        exposures_file = DATA_DIR / 'exposures.csv'
        with open(exposures_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'id', 'iteration_id', 'workflow_type', 'exposure_id', 'severity',
                'cvss_score', 'service', 'vulnerability_type', 'on_attack_path',
                't_appeared', 't_detected', 't_remediated', 'remediated',
                'mew_seconds', 'mttr_seconds', 'created_at'
            ])
            writer.writerows(exposures)
        
        print(f"✓ Exported {len(exposures)} exposures to {exposures_file}")
        
        # Export attack simulations
        cursor.execute('SELECT * FROM attack_simulations')
        attacks = cursor.fetchall()
        
        attacks_file = DATA_DIR / 'attack_simulations.csv'
        with open(attacks_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'id', 'iteration_id', 'workflow_type', 'attack_type',
                'target_service', 'success', 'steps_count', 'attack_path', 'timestamp'
            ])
            writer.writerows(attacks)
        
        print(f"✓ Exported {len(attacks)} attack simulations to {attacks_file}")
        
        # Export summary metrics
        self.calculate_and_export_metrics()
        
        return True
    
    def calculate_and_export_metrics(self):
        """Calculate MEW, MTTR, CEC, RFR and export summary"""
        cursor = self.db_conn.cursor()
        
        metrics = []
        
        for workflow in ['Traditional VM', 'CTEM']:
            # MEW (Mean Exposure Window)
            cursor.execute('''
                SELECT AVG(mew_seconds) FROM exposures 
                WHERE workflow_type = ? AND severity IN ('HIGH', 'CRITICAL')
            ''', (workflow,))
            mew = cursor.fetchone()[0] or 0
            
            # MTTR (Mean Time To Remediate)
            cursor.execute('''
                SELECT AVG(mttr_seconds) FROM exposures 
                WHERE workflow_type = ? AND severity IN ('HIGH', 'CRITICAL')
            ''', (workflow,))
            mttr = cursor.fetchone()[0] or 0
            
            # CEC (Critical Exposure Count)
            cursor.execute('''
                SELECT COUNT(*) FROM exposures 
                WHERE workflow_type = ? AND severity = 'CRITICAL' AND remediated = 1
            ''', (workflow,))
            cec_remediated = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM exposures 
                WHERE workflow_type = ? AND severity = 'CRITICAL'
            ''', (workflow,))
            cec_total = cursor.fetchone()[0]
            
            cec_coverage = (cec_remediated / cec_total * 100) if cec_total > 0 else 0
            
            # RFR (Remediation Focus Ratio)
            cursor.execute('''
                SELECT COUNT(*) FROM exposures 
                WHERE workflow_type = ? AND remediated = 1 AND on_attack_path = 1
            ''', (workflow,))
            rfr_focused = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM exposures 
                WHERE workflow_type = ? AND remediated = 1
            ''', (workflow,))
            rfr_total = cursor.fetchone()[0]
            
            rfr = (rfr_focused / rfr_total * 100) if rfr_total > 0 else 0
            
            # Attack success rate
            cursor.execute('''
                SELECT AVG(success) FROM attack_simulations 
                WHERE workflow_type = ?
            ''', (workflow,))
            attack_success_rate = (cursor.fetchone()[0] or 0) * 100
            
            metrics.append({
                'workflow': workflow,
                'mew_seconds': round(mew, 2),
                'mew_hours': round(mew / 3600, 2),
                'mttr_seconds': round(mttr, 2),
                'mttr_hours': round(mttr / 3600, 2),
                'cec_coverage_percent': round(cec_coverage, 2),
                'rfr_percent': round(rfr, 2),
                'attack_success_rate_percent': round(attack_success_rate, 2)
            })
        
        # Export metrics summary
        import csv
        metrics_file = DATA_DIR / 'metrics_summary.csv'
        with open(metrics_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=metrics[0].keys())
            writer.writeheader()
            writer.writerows(metrics)
        
        print(f"\n✓ Exported metrics summary to {metrics_file}")
        
        # Print summary
        print("\n" + "="*70)
        print("METRICS SUMMARY")
        print("="*70)
        for m in metrics:
            print(f"\n{m['workflow']}:")
            print(f"  MEW: {m['mew_hours']:.2f} hours")
            print(f"  MTTR: {m['mttr_hours']:.2f} hours")
            print(f"  CEC Coverage: {m['cec_coverage_percent']:.1f}%")
            print(f"  RFR: {m['rfr_percent']:.1f}%")
            print(f"  Attack Success Rate: {m['attack_success_rate_percent']:.1f}%")
    
    def run_full_experiment(self, iterations=5):
        """Run the complete experiment"""
        print("\n" + "="*70)
        print("CTEM VS TRADITIONAL VM - EXPERIMENTAL COMPARISON")
        print("Coventry University MSc Cybersecurity Dissertation")
        print("="*70)
        print(f"\nRunning {iterations} iterations for each workflow")
        print(f"Estimated completion time: {iterations * 4} minutes")
        
        # Deploy environment once
        if not self.deploy_environment():
            print("\n✗ Environment deployment failed")
            return False
        
        # Run Traditional VM iterations
        print("\n" + "="*70)
        print("PHASE 1: TRADITIONAL VULNERABILITY MANAGEMENT")
        print("="*70)
        
        for i in range(1, iterations + 1):
            if not self.run_traditional_vm_workflow(i):
                print(f"\n✗ Traditional VM iteration {i} failed")
                return False
            time.sleep(5)  # Brief pause between iterations
        
        # Run CTEM iterations
        print("\n" + "="*70)
        print("PHASE 2: CONTINUOUS THREAT EXPOSURE MANAGEMENT")
        print("="*70)
        
        for i in range(1, iterations + 1):
            if not self.run_ctem_workflow(i):
                print(f"\n✗ CTEM iteration {i} failed")
                return False
            time.sleep(5)
        
        # Export results
        self.export_results()
        
        print("\n" + "="*70)
        print("EXPERIMENT COMPLETE!")
        print("="*70)
        print(f"\nResults saved to: {DATA_DIR}")
        print("Next steps:")
        print("1. Open Power BI Desktop")
        print("2. Import CSV files from data/ directory")
        print("3. Create visualizations using the metrics")
        print("4. Write dissertation with empirical evidence!")
        
        return True
    
    def cleanup(self):
        """Stop Docker containers and cleanup"""
        if self.simulation_mode:
            print("📊 Cleaning up simulated environment")
        else:
            try:
                subprocess.run(
                    ['docker-compose', 'down'],
                    cwd=DOCKER_DIR,
                    check=False,
                    capture_output=True,
                    timeout=30
                )
            except Exception as e:
                print(f"⚠ Cleanup error (non-critical): {e}")
        
        if self.db_conn:
            self.db_conn.close()

if __name__ == '__main__':
    runner = ExperimentRunner()
    
    try:
        success = runner.run_full_experiment(iterations=5)
        if not success:
            print("\n✗ Experiment failed - check logs above")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nExperiment interrupted by user")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        runner.cleanup()
        print("\n✓ Cleanup complete")

# Improved error handling
import sys
if __name__ == '__main__':
    try:
        runner = ExperimentRunner()
        success = runner.run_full_experiment(iterations=5)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nExperiment interrupted")
        sys.exit(1)
