#!/usr/bin/env python3

import random
from datetime import datetime, timedelta

class VMScanningContextAnalyzer:
    def __init__(self):
        # Scanning schedule (traditional approach)
        self.scan_schedules = {
            'DVWA': {'frequency': 'weekly', 'last_scan': None},
            'API': {'frequency': 'weekly', 'last_scan': None},
            'MySQL': {'frequency': 'monthly', 'last_scan': None}
        }
        
        # Compliance frameworks (PCI-DSS, HIPAA, etc.)
        self.compliance_requirements = {
            'CVSS_threshold': 4.0,  # Anything above this must be reported
            'scan_frequency': 'weekly',
            'report_format': 'CVSS-based',
            'remediation_sla': {
                'CRITICAL': 14,  # 14 days
                'HIGH': 30,      # 30 days
                'MEDIUM': 90,    # 90 days
                'LOW': 180       # 180 days
            }
        }
        
        # Scanning tools simulated
        self.scanning_tools = ['Nessus', 'Qualys', 'Rapid7', 'OpenVAS']
        
        # Baseline and trending data
        self.historical_scans = []
    
    def schedule_and_execute_scan(self, vulnerabilities):
        scanned = []
        scan_time = datetime.now()
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Add scan metadata
            vuln_copy['scan_time'] = scan_time
            vuln_copy['scan_tool'] = random.choice(self.scanning_tools)
            vuln_copy['detected_by_scan'] = True
            
            # Simulate scanner detection confidence
            # Higher CVSS = higher confidence
            vuln_copy['detection_confidence'] = min(vuln['cvss_score'] / 10.0, 1.0)
            
            # Add scan cycle information
            service_schedule = self.scan_schedules.get(vuln['service'], {})
            vuln_copy['scheduled_frequency'] = service_schedule.get('frequency', 'ad-hoc')
            
            scanned.append(vuln_copy)
        
        self.historical_scans.append({
            'scan_date': scan_time,
            'vulnerabilities_found': len(scanned),
            'high_severity_count': len([v for v in scanned if v['severity'] in ['HIGH', 'CRITICAL']])
        })
        
        return scanned
    
    def apply_cvss_prioritization(self, vulnerabilities):
        prioritized = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # CVSS is the primary prioritization metric in traditional scanning
            vuln_copy['priority_score'] = vuln['cvss_score']
            
            # Add CVSS-based severity tier
            cvss = vuln['cvss_score']
            if cvss >= 9.0:
                vuln_copy['severity_tier'] = 'CRITICAL'
                vuln_copy['response_time_sla'] = 'Immediate'
            elif cvss >= 7.0:
                vuln_copy['severity_tier'] = 'HIGH'
                vuln_copy['response_time_sla'] = 'Within 14 days'
            elif cvss >= 4.0:
                vuln_copy['severity_tier'] = 'MEDIUM'
                vuln_copy['response_time_sla'] = 'Within 30 days'
            else:
                vuln_copy['severity_tier'] = 'LOW'
                vuln_copy['response_time_sla'] = 'Within 90 days'
            
            # Add compliance requirement status
            vuln_copy['compliance_required_fix'] = cvss >= self.compliance_requirements['CVSS_threshold']
            
            prioritized.append(vuln_copy)
        
        # Sort by CVSS score descending
        return sorted(prioritized, key=lambda x: x['priority_score'], reverse=True)
    
    def create_remediation_tickets(self, vulnerabilities):
        #Create remediation tickets for report generation
        #Only creates tickets for vulnerabilities meeting compliance threshold
        tickets = []
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            # Only create tickets for findings that meet compliance requirements
            if vuln['cvss_score'] < self.compliance_requirements['CVSS_threshold']:
                continue
            
            severity = vuln['severity']
            sla_days = self.compliance_requirements['remediation_sla'].get(severity, 90)
            
            ticket = {
                'ticket_id': f"VM-{idx:05d}",
                'vulnerability_id': vuln['id'],
                'status': 'OPEN',
                'severity': severity,
                'cvss': vuln['cvss_score'],
                'service': vuln['service'],
                'type': vuln['type'],
                'created_date': datetime.now(),
                'due_date': datetime.now() + timedelta(days=sla_days),
                'sla_days': sla_days,
                'assigned_to': 'IT Security Team',
                'remediation_strategy': f"Apply security patch for {vuln['type']}",
                'verification_method': 'Re-scan with {}'.format(random.choice(self.scanning_tools))
            }
            
            tickets.append(ticket)
        
        return tickets
    
    def track_remediation_progress(self, vulnerabilities, tickets):
        progress = {
            'total_vulnerabilities': len(vulnerabilities),
            'tickets_created': len(tickets),
            'open_tickets': len([t for t in tickets if t['status'] == 'OPEN']),
            'closed_tickets': len([t for t in tickets if t['status'] == 'CLOSED']),
            'overdue_tickets': 0,
            'by_severity': {
                'CRITICAL': {'open': 0, 'closed': 0, 'overdue': 0},
                'HIGH': {'open': 0, 'closed': 0, 'overdue': 0},
                'MEDIUM': {'open': 0, 'closed': 0, 'overdue': 0},
                'LOW': {'open': 0, 'closed': 0, 'overdue': 0}
            }
        }
        
        for ticket in tickets:
            severity = ticket['severity']
            
            if ticket['status'] == 'OPEN':
                progress['by_severity'][severity]['open'] += 1
                
                # Check if overdue
                if datetime.now() > ticket['due_date']:
                    progress['by_severity'][severity]['overdue'] += 1
                    progress['overdue_tickets'] += 1
            else:
                progress['by_severity'][severity]['closed'] += 1
        
        return progress
    
    def generate_compliance_report(self, vulnerabilities, progress):
        """
        Generate compliance status report
        Shows adherence to compliance requirements (PCI-DSS, etc.)
        """
        report = {
            'report_date': datetime.now(),
            'compliance_framework': 'PCI-DSS v3.2.1',
            'compliance_status': 'COMPLIANT' if progress['overdue_tickets'] == 0 else 'NON-COMPLIANT',
            'critical_findings': len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
            'high_findings': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
            'remediation_stats': {
                'total_open': progress['open_tickets'],
                'total_overdue': progress['overdue_tickets'],
                'remediation_rate': round((progress['closed_tickets'] / (progress['tickets_created'] or 1)) * 100, 2)
            },
            'metrics': {
                'mean_time_to_detect': 'Unknown (scheduled scans)',
                'mean_time_to_remediate': 'Based on SLA',
                'compliance_violation_count': progress['overdue_tickets'],
                'audit_findings': []
            }
        }
        
        # Add audit findings for overdue items
        if progress['overdue_tickets'] > 0:
            report['metrics']['audit_findings'].append(
                f"{progress['overdue_tickets']} critical/high severity items exceed remediation SLA"
            )
        
        return report
    
    def iterate_scanning_cycle(self, vulnerabilities):
        """
        Simulate multiple scanning cycles showing traditional VMS patterns
        Shows improvements over time with patching
        """
        cycles = []
        
        for cycle_num in range(1, 4):  # 3 scan cycles
            cycle_data = {
                'cycle': cycle_num,
                'scan_date': datetime.now() + timedelta(days=cycle_num*7),
                'total_found': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
                'high_count': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
                'new_vulnerabilities': max(0, len(vulnerabilities) - (cycle_num * 2)),
                'resolved_vulnerabilities': cycle_num * 2,
                'false_positives': random.randint(0, 2)
            }
            cycles.append(cycle_data)
        
        return cycles
    
    def compare_scan_trends(self, scan_cycles):
        trend_analysis = {
            'total_trend': 'IMPROVING' if scan_cycles[-1]['total_found'] < scan_cycles[0]['total_found'] else 'WORSENING',
            'critical_trend': 'IMPROVING' if scan_cycles[-1]['critical_count'] < scan_cycles[0]['critical_count'] else 'STABLE',
            'remediation_velocity': sum([c['resolved_vulnerabilities'] for c in scan_cycles]),
            'discovery_rate': sum([c['new_vulnerabilities'] for c in scan_cycles]),
            'trend_summary': 'Vulnerability count decreasing - remediation efforts appear effective'
        }
        
        return trend_analysis

    def calculate_metrics(self, vulnerabilities, tickets=None):
        """
        Calculate VM scanning-specific metrics
        Focus: CVSS-based statistics, detection confidence, ticket tracking, compliance
        """
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        avg_cvss = round(sum(v.get('cvss_score', 0) for v in vulnerabilities) / total, 2) if total else 0
        avg_confidence = round(sum(v.get('detection_confidence', 0) for v in vulnerabilities) / total, 2) if total else 0
        tickets_created = len(tickets) if tickets is not None else 0
        open_tickets = len([t for t in tickets if t.get('status') == 'OPEN']) if tickets is not None else 0
        
        # Calculate compliance metrics
        compliance_violations = len([v for v in vulnerabilities 
                                    if v.get('cvss_score', 0) >= self.compliance_requirements['CVSS_threshold'] 
                                    and v.get('severity') in ['CRITICAL', 'HIGH']])
        
        # Exploitable concept (CVSS >= 7.0 typical high risk threshold)
        exploitable = len([v for v in vulnerabilities if v.get('cvss_score', 0) >= 7.0])
        avg_priority = round(sum(v.get('priority_score', 0) for v in vulnerabilities) / total, 2) if total else 0

        return {
            'context': 'VMScanning',
            'total_vulnerabilities': total,
            'critical': critical,
            'high': high,
            'avg_cvss': avg_cvss,
            'avg_detection_confidence': avg_confidence,
            'tickets_created': tickets_created,
            'open_tickets': open_tickets,
            'compliance_violations': compliance_violations,
            'exploitable': exploitable,
            'avg_exploit_priority': avg_priority,
            # Standardized keys for comparison
            'avg_exploit_probability': 0,
            'avg_exposure_criticality': 0,
            'external_exposure': 0,
            'internal_exposure': 0
        }


if __name__ == '__main__':
    from vulnerability_scanner import VulnerabilityScanner
    
    scanner = VulnerabilityScanner()
    vulns = scanner.scan_targets(['http://localhost:8080', 'localhost:3306', 'http://localhost:3000'])
    
    analyzer = VMScanningContextAnalyzer()
    
    print("\nVULNERABILITY MANAGEMENT SCANNING METHODOLOGY")
    
    # Run VMS workflow
    scanned = analyzer.schedule_and_execute_scan(vulns)
    print(f"\nScanned Vulnerabilities: {len(scanned)}")
    
    prioritized = analyzer.apply_cvss_prioritization(scanned)
    print(f"Prioritized by CVSS: {len(prioritized)}")
    
    tickets = analyzer.create_remediation_tickets(prioritized)
    print(f"Remediation Tickets Created: {len(tickets)}")
    
    progress = analyzer.track_remediation_progress(prioritized, tickets)
    print(f"\nProgress Tracking:")
    print(f"  Open Tickets: {progress['open_tickets']}")
    print(f"  Closed Tickets: {progress['closed_tickets']}")
    print(f"  Overdue Tickets: {progress['overdue_tickets']}")
    
    compliance = analyzer.generate_compliance_report(prioritized, progress)
    print(f"\nCompliance Status: {compliance['compliance_status']}")
    
    cycles = analyzer.iterate_scanning_cycle(prioritized)
    print(f"Scanning Cycles Projected: {len(cycles)}")
    
    trends = analyzer.compare_scan_trends(cycles)
    print(f"Trend Analysis: {trends['total_trend']}")
