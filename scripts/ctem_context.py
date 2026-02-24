#!/usr/bin/env python3
import random

class CTEMContextAnalyzer:
    def __init__(self):
        # Asset criticality mapping
        self.asset_criticality = {
            'DVWA': 'HIGH',      # Customer-facing web app
            'MySQL': 'CRITICAL', # Contains PII/sensitive data
            'API': 'CRITICAL'    # Core business functionality
        }
        
        # Threat intelligence feed (simulated)
        self.active_threats = [
            'SQL Injection',
            'Weak Password',
            'Command Injection'
        ]
    
    def add_business_context(self, vulnerabilities):
        #Add business context to each vulnerability
        #CTEM differentiator: Considers business impact, not just technical severity
        contextualized = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Add asset criticality
            vuln_copy['asset_criticality'] = self.asset_criticality.get(
                vuln['service'], 
                'MEDIUM'
            )
            
            # Check if actively exploited in the wild
            vuln_copy['actively_exploited'] = vuln['type'] in self.active_threats
            
            # Add exposure context
            if vuln['service'] == 'DVWA':
                vuln_copy['exposure'] = 'EXTERNAL'  # Internet-facing
            elif vuln['service'] == 'API':
                vuln_copy['exposure'] = 'EXTERNAL'
            else:
                vuln_copy['exposure'] = 'INTERNAL'
            
            # Add data sensitivity
            if vuln['service'] == 'MySQL':
                vuln_copy['data_sensitivity'] = 'PII/Financial'
            else:
                vuln_copy['data_sensitivity'] = 'Standard'
            
            contextualized.append(vuln_copy)
        
        return contextualized
    
    def prioritize_by_risk(self, vulnerabilities):
        """
        CTEM Risk-based prioritization (vs CVSS-only)
        
        Risk Score = f(CVSS, Business Impact, Exploitability, Threat Intel)
        """
        prioritized = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Start with CVSS
            risk_score = vuln['cvss_score']
            
            # Adjust for business context
            if vuln_copy.get('asset_criticality') == 'CRITICAL':
                risk_score += 1.5
            elif vuln_copy.get('asset_criticality') == 'HIGH':
                risk_score += 1.0
            
            # Adjust for active exploitation
            if vuln_copy.get('actively_exploited'):
                risk_score += 2.0
            
            # Adjust for exposure
            if vuln_copy.get('exposure') == 'EXTERNAL':
                risk_score += 1.0
            
            # Adjust for data sensitivity
            if 'PII' in vuln_copy.get('data_sensitivity', ''):
                risk_score += 1.5
            
            # Cap at 10.0
            risk_score = min(risk_score, 10.0)
            
            vuln_copy['risk_score'] = round(risk_score, 2)
            prioritized.append(vuln_copy)
        
        # Sort by risk score (descending)
        return sorted(prioritized, key=lambda x: x['risk_score'], reverse=True)
    
    def validate_exploitability(self, vulnerabilities):
        """
        CTEM Validation: Simulate breach and attack simulation (BAS)
        
        Determines which vulnerabilities are actually exploitable
        """
        validated = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Simulate exploitation attempt
            # High CVSS + High Risk = More likely exploitable
            exploit_probability = (
                (vuln['cvss_score'] / 10.0) * 0.5 +
                (vuln_copy.get('risk_score', 5) / 10.0) * 0.5
            )
            
            # Critical vulnerabilities more likely to be exploitable
            if vuln['severity'] == 'CRITICAL':
                exploit_probability += 0.2
            
            # Active threats definitely exploitable
            if vuln_copy.get('actively_exploited'):
                exploit_probability = 1.0
            
            vuln_copy['exploitable'] = random.random() < exploit_probability
            vuln_copy['exploit_probability'] = round(exploit_probability, 2)
            
            validated.append(vuln_copy)
        
        return validated
    
    def identify_attack_paths(self, vulnerabilities):
        """
        Identify attack paths to critical assets
        
        CTEM focuses on breaking attack chains, not just fixing individual vulns
        """
        attack_paths = []
        
        # Simplified attack path logic
        # Real CTEM would use attack graph analysis
        
        # Path 1: External -> DVWA SQL -> MySQL compromise
        dvwa_sql = [v for v in vulnerabilities 
                    if v['service'] == 'DVWA' and 'SQL' in v['type']]
        if dvwa_sql:
            attack_paths.append({
                'path_id': 'PATH-001',
                'steps': ['External Access', 'DVWA SQLi', 'Database Compromise'],
                'impact': 'Data Breach (PII Exposure)',
                'likelihood': 'HIGH',
                'vulnerabilities': [dvwa_sql[0]['id']]
            })
        
        # Path 2: API authentication bypass -> Database access
        api_auth = [v for v in vulnerabilities 
                    if v['service'] == 'API' and 'Authentication' in v['type']]
        if api_auth:
            attack_paths.append({
                'path_id': 'PATH-002',
                'steps': ['External Access', 'API Auth Bypass', 'Database Access'],
                'impact': 'Unauthorized Data Access',
                'likelihood': 'HIGH',
                'vulnerabilities': [api_auth[0]['id']]
            })
        
        # Path 3: MySQL weak password -> Full system compromise
        mysql_weak = [v for v in vulnerabilities 
                      if v['service'] == 'MySQL' and 'Password' in v['type']]
        if mysql_weak:
            attack_paths.append({
                'path_id': 'PATH-003',
                'steps': ['Network Access', 'MySQL Brute Force', 'Data Exfiltration'],
                'impact': 'Complete Data Breach',
                'likelihood': 'CRITICAL',
                'vulnerabilities': [mysql_weak[0]['id']]
            })
        
        return attack_paths

if __name__ == '__main__':
    # Test
    from vulnerability_scanner import VulnerabilityScanner
    
    scanner = VulnerabilityScanner()
    vulns = scanner.scan_targets(['http://localhost:8080', 'localhost:3306'])
    
    analyzer = CTEMContextAnalyzer()
    contextualized = analyzer.add_business_context(vulns)
    prioritized = analyzer.prioritize_by_risk(contextualized)
    validated = analyzer.validate_exploitability(prioritized)
    
    print("\nTop 5 Risks (CTEM Prioritization):")
    for v in validated[:5]:
        print(f"  {v['type']}: Risk={v['risk_score']}, Exploitable={v['exploitable']}")
