#!/usr/bin/env python3
"""
Attack Surface Discovery (ASD) Methodology Context
Focuses on identifying and mapping all external-facing assets and entry points
"""

import random

class AttackSurfaceDiscoveryAnalyzer:
    def __init__(self):
        # Asset inventory from ASD process
        self.discovered_assets = {
            'DVWA': {'type': 'Web Application', 'exposure': 'EXTERNAL', 'port': 8080},
            'API': {'type': 'REST API', 'exposure': 'EXTERNAL', 'port': 3000},
            'MySQL': {'type': 'Database', 'exposure': 'INTERNAL', 'port': 3306}
        }
        
        # Attack surface mapping
        self.entry_points = [
            'Web Form Submission',
            'API Endpoint',
            'Database Connection',
            'Network Service',
            'File Upload'
        ]
        
        # Technology detection
        self.tech_stack = {
            'DVWA': ['PHP', 'MySQL', 'jQuery'],
            'API': ['Node.js', 'Express', 'MongoDB'],
            'MySQL': ['MySQL 5.7', 'InnoDB']
        }
    
    def discover_assets(self, vulnerabilities):
        """
        Map attack surface by discovering all assets
        ASD focuses on what's exposed, not just vulnerabilities
        """
        assets_found = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Add asset discovery information
            if vuln['service'] in self.discovered_assets:
                asset_info = self.discovered_assets[vuln['service']]
                vuln_copy['asset_type'] = asset_info['type']
                vuln_copy['asset_exposure'] = asset_info['exposure']
                vuln_copy['asset_port'] = asset_info['port']
                
                # Add detected technologies
                vuln_copy['detected_technologies'] = self.tech_stack.get(vuln['service'], [])
                
                # Add entry point mapping
                if asset_info['exposure'] == 'EXTERNAL':
                    vuln_copy['entry_points'] = ['Web Form Submission', 'API Endpoint', 'HTTP Request']
                else:
                    vuln_copy['entry_points'] = ['Network Protocol', 'Direct Connection']
                
                assets_found.append(vuln_copy)
        
        return assets_found
    
    def analyze_exposure_paths(self, vulnerabilities):
        """
        Analyze how each vulnerability exposes attack surface
        Maps the path from external attacker to vulnerable component
        """
        with_exposure_paths = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            # Map exposure path based on service and type
            if vuln['service'] == 'DVWA':
                if 'SQL' in vuln['type']:
                    exposure_path = {
                        'entry': 'DVWA Web Form',
                        'intermediate': 'PHP Application Logic',
                        'target': 'MySQL Database',
                        'hops': 2,
                        'attacker_access_level': 'Unauthenticated'
                    }
                elif 'XSS' in vuln['type']:
                    exposure_path = {
                        'entry': 'DVWA Web Form',
                        'intermediate': 'Browser Execution',
                        'target': 'User Session',
                        'hops': 1,
                        'attacker_access_level': 'Unauthenticated'
                    }
                else:
                    exposure_path = {
                        'entry': 'DVWA Web Form',
                        'intermediate': 'Application',
                        'target': 'Backend System',
                        'hops': 1,
                        'attacker_access_level': 'Unauthenticated'
                    }
            
            elif vuln['service'] == 'API':
                exposure_path = {
                    'entry': 'API Endpoint',
                    'intermediate': 'REST Handler',
                    'target': 'Application Logic',
                    'hops': 1,
                    'attacker_access_level': 'Unauthenticated'
                }
            
            else:  # MySQL
                if 'Default Credentials' in vuln['type'] or 'Password' in vuln['type']:
                    exposure_path = {
                        'entry': 'Network Port 3306',
                        'intermediate': 'MySQL Authentication',
                        'target': 'Database Engine',
                        'hops': 0,
                        'attacker_access_level': 'Brute Force'
                    }
                else:
                    exposure_path = {
                        'entry': 'Network Port 3306',
                        'intermediate': 'MySQL Service',
                        'target': 'Database Engine',
                        'hops': 0,
                        'attacker_access_level': 'Network Access'
                    }
            
            vuln_copy['exposure_path'] = exposure_path
            with_exposure_paths.append(vuln_copy)
        
        return with_exposure_paths
    
    def prioritize_by_exposure_criticality(self, vulnerabilities):
        """
        ASD prioritization: Based on how exposed/accessible the vulnerability is
        
        Factors:
        1. Asset exposure (external vs internal)
        2. Number of entry points
        3. Authentication required
        4. Severity combined with accessibility
        """
        prioritized = []
        
        for vuln in vulnerabilities:
            vuln_copy = vuln.copy()
            
            exposure_score = 0
            
            # Weight external exposure heavily
            if vuln_copy.get('asset_exposure') == 'EXTERNAL':
                exposure_score += 4
            else:
                exposure_score += 1
            
            # Factor in number of entry points
            entry_points = len(vuln_copy.get('entry_points', []))
            exposure_score += entry_points
            
            # Unauthenticated access increases exposure
            if 'Unauthenticated' in vuln_copy.get('exposure_path', {}).get('attacker_access_level', ''):
                exposure_score += 2
            
            # CVSS severity still matters
            exposure_score += (vuln['cvss_score'] / 10.0)
            
            # Critical severity gets boost
            if vuln['severity'] == 'CRITICAL':
                exposure_score += 1.5
            
            vuln_copy['exposure_criticality_score'] = round(min(exposure_score, 10.0), 2)
            prioritized.append(vuln_copy)
        
        return sorted(prioritized, key=lambda x: x['exposure_criticality_score'], reverse=True)
    
    def map_attack_surface_zones(self, vulnerabilities):
        """
        Group vulnerabilities into attack surface zones
        Shows where the organization's risks are concentrated
        """
        zones = {}
        
        for vuln in vulnerabilities:
            zone = vuln.get('asset_exposure', 'UNKNOWN')
            
            if zone not in zones:
                zones[zone] = {
                    'exposure_type': zone,
                    'vulnerabilities': [],
                    'critical_count': 0,
                    'high_count': 0,
                    'avg_cvss': 0
                }
            
            zones[zone]['vulnerabilities'].append(vuln['id'])
            
            if vuln['severity'] == 'CRITICAL':
                zones[zone]['critical_count'] += 1
            elif vuln['severity'] == 'HIGH':
                zones[zone]['high_count'] += 1
        
        # Calculate averages
        for zone_data in zones.values():
            zone_vulns = [v for v in vulnerabilities if v['id'] in zone_data['vulnerabilities']]
            if zone_vulns:
                zone_data['avg_cvss'] = round(sum(v['cvss_score'] for v in zone_vulns) / len(zone_vulns), 2)
                zone_data['vuln_count'] = len(zone_vulns)
        
        return zones
    
    def identify_asset_inventory_gaps(self, vulnerabilities):
        """
        Identify what might be missing from the discovered attack surface
        ASD continuously looks for new/undiscovered assets
        """
        gaps = []
        
        # Check if all expected services were found
        expected_services = ['DVWA', 'API', 'MySQL']
        found_services = set(v['service'] for v in vulnerabilities)
        
        for service in expected_services:
            if service not in found_services:
                gaps.append({
                    'type': 'Missing Asset',
                    'expected_service': service,
                    'risk': 'Cannot assess security posture of undiscovered asset',
                    'recommendation': 'Run comprehensive asset discovery scan'
                })
        
        # Check for unusual patterns that might indicate new assets
        ports_found = set(v.get('asset_port') for v in vulnerabilities if 'asset_port' in v)
        if len(ports_found) < 3:
            gaps.append({
                'type': 'Limited Port Coverage',
                'ports_found': len(ports_found),
                'risk': 'May be missing services on non-standard ports',
                'recommendation': 'Conduct full port scan across all ranges'
            })
        
        return gaps
    
    def generate_surface_map_report(self, vulnerabilities):
        """
        Generate attack surface map showing all discovered elements
        """
        report = {
            'total_assets': len(set(v['service'] for v in vulnerabilities)),
            'external_assets': len(set(v['service'] for v in vulnerabilities if v.get('asset_exposure') == 'EXTERNAL')),
            'internal_assets': len(set(v['service'] for v in vulnerabilities if v.get('asset_exposure') == 'INTERNAL')),
            'total_entry_points': sum(len(v.get('entry_points', [])) for v in vulnerabilities),
            'vulnerabilities_by_exposure': {},
            'technologies_identified': set()
        }
        
        for vuln in vulnerabilities:
            exposure = vuln.get('asset_exposure', 'UNKNOWN')
            if exposure not in report['vulnerabilities_by_exposure']:
                report['vulnerabilities_by_exposure'][exposure] = 0
            report['vulnerabilities_by_exposure'][exposure] += 1
            
            for tech in vuln.get('detected_technologies', []):
                report['technologies_identified'].add(tech)
        
        report['technologies_identified'] = list(report['technologies_identified'])
        
        return report

    def calculate_metrics(self, vulnerabilities):
        """
        Calculate ASD-specific metrics
        ASD focus: exposure surface, asset inventory, entry points
        """
        total = len(vulnerabilities)
        severity_counts = {
            'CRITICAL': len([v for v in vulnerabilities if v['severity'] == 'CRITICAL']),
            'HIGH': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
            'MEDIUM': len([v for v in vulnerabilities if v['severity'] == 'MEDIUM']),
            'LOW': len([v for v in vulnerabilities if v['severity'] == 'LOW'])
        }
        avg_cvss = round(sum(v['cvss_score'] for v in vulnerabilities) / total, 2) if total else 0
        avg_exposure_criticality = round(sum(v.get('exposure_criticality_score', 0) for v in vulnerabilities) / total, 2) if total else 0
        external = len([v for v in vulnerabilities if v.get('asset_exposure') == 'EXTERNAL'])
        internal = len([v for v in vulnerabilities if v.get('asset_exposure') == 'INTERNAL'])
        
        exploitable = len([v for v in vulnerabilities if v.get('exposure_criticality_score', 0) >= 7.0])
        avg_exploit_priority = round(sum(v.get('exposure_criticality_score', 0) for v in vulnerabilities) / total, 2) if total else 0
        total_entry_points = sum(len(v.get('entry_points', [])) for v in vulnerabilities)

        return {
            'context': 'AttackSurfaceDiscovery',
            'total_vulnerabilities': total,
            'critical': severity_counts['CRITICAL'],
            'high': severity_counts['HIGH'],
            'avg_cvss': avg_cvss,
            'avg_exposure_criticality': avg_exposure_criticality,
            'external_exposure': external,
            'internal_exposure': internal,
            'total_entry_points': total_entry_points,
            'exploitable': exploitable,
            'avg_exploit_priority': avg_exploit_priority,
            'avg_exploit_probability': 0,
            'avg_detection_confidence': 0,
            'tickets_created': 0,
            'open_tickets': 0
        }


if __name__ == '__main__':
    from vulnerability_scanner import VulnerabilityScanner
    scanner = VulnerabilityScanner()
    vulns = scanner.scan_targets(['http://localhost:8080', 'localhost:3306', 'http://localhost:3000'])
    
    analyzer = AttackSurfaceDiscoveryAnalyzer()
    
    print("\n=== ATTACK SURFACE DISCOVERY METHODOLOGY ===")
    
    # Run ASD workflow
    assets = analyzer.discover_assets(vulns)
    print(f"\nAssets Discovered: {len(assets)}")
    
    with_paths = analyzer.analyze_exposure_paths(assets)
    print(f"Exposure Paths Mapped: {len(with_paths)}")
    
    prioritized = analyzer.prioritize_by_exposure_criticality(with_paths)
    print(f"Prioritized by Exposure Criticality: {len(prioritized)}")
    
    report = analyzer.generate_surface_map_report(prioritized)
    print(f"\nAttack Surface Report:")
    print(f"  Total Assets: {report['total_assets']}")
    print(f"  External Exposure: {report['external_assets']}")
    print(f"  Total Entry Points: {report['total_entry_points']}")
    print(f"  Technologies Identified: {len(report['technologies_identified'])}")
