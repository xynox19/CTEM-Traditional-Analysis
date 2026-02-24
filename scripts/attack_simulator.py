#!/usr/bin/env python3
import random
import time

class AttackSimulator:    
    def __init__(self):
        self.attack_scenarios = [
            {
                'name': 'SQL Injection Attack',
                'target': 'DVWA',
                'steps': [
                    'Reconnaissance', 
                    'Input Fuzzing',
                    'SQL Injection Payload',
                    'Data Extraction'
                ],
                'success_rate_base': 0.9
            },
            {
                'name': 'Authentication Bypass',
                'target': 'API',
                'steps': [
                    'Endpoint Discovery',
                    'Auth Token Analysis',
                    'JWT Forgery',
                    'Unauthorized Access'
                ],
                'success_rate_base': 0.85
            },
            {
                'name': 'Database Compromise',
                'target': 'MySQL',
                'steps': [
                    'Port Scanning',
                    'Credential Brute Force',
                    'Database Connection',
                    'Data Exfiltration'
                ],
                'success_rate_base': 0.8
            },
            {
                'name': 'Command Injection',
                'target': 'DVWA',
                'steps': [
                    'Function Discovery',
                    'Payload Crafting',
                    'Command Execution',
                    'Reverse Shell'
                ],
                'success_rate_base': 0.75
            },
            {
                'name': 'Path Traversal',
                'target': 'API',
                'steps': [
                    'Directory Enumeration',
                    'Path Manipulation',
                    'File Access',
                    'Sensitive Data Retrieval'
                ],
                'success_rate_base': 0.7
            }
        ]
    
    def simulate_attacks(self, target_host, after_remediation=False):
        """
        Simulate attack attempts
        
        Args:
            target_host: Target system
            after_remediation: If True, success rates are reduced
            
        Returns:
            List of attack results
        """
        results = []
        
        remediation_factor = 0.3 if after_remediation else 1.0
        
        for scenario in self.attack_scenarios:
            # Simulate attack
            success_rate = scenario['success_rate_base'] * remediation_factor
            
            # Add randomness
            success = random.random() < success_rate
            
            # Calculate steps taken
            if success:
                steps_used = len(scenario['steps'])
                final_path = scenario['steps']
            else:
                # Failed attacks don't complete all steps
                steps_used = random.randint(1, len(scenario['steps']) - 1)
                final_path = scenario['steps'][:steps_used]
            
            results.append({
                'type': scenario['name'],
                'target': scenario['target'],
                'success': 1 if success else 0,
                'steps': steps_used,
                'path': final_path,
                'timestamp': time.time()
            })
        
        return results
    
    def test_specific_vulnerability(self, vuln_type, service):
        """Test if a specific vulnerability is still exploitable"""
        # Simplified exploitation test
        exploit_configs = {
            'SQL Injection': {
                'payloads': ["' OR '1'='1", "1' UNION SELECT NULL--"],
                'success_indicators': ['error', 'database', 'syntax']
            },
            'Weak Password': {
                'payloads': ['admin:admin', 'root:root', 'admin:password'],
                'success_indicators': ['Welcome', 'logged in', 'session']
            },
            'Command Injection': {
                'payloads': ['; ls', '| whoami', '&& cat /etc/passwd'],
                'success_indicators': ['root:', 'bin', 'uid=']
            }
        }
        
        config = exploit_configs.get(vuln_type, {})
        
        # Simulate exploitation attempt
        if config:
            success_rate = 0.8  # 80% success if vulnerability exists
            return random.random() < success_rate
        
        return False

if __name__ == '__main__':
    simulator = AttackSimulator()
    
    print("\n Attack Simulation (Before Remediation) ")
    results_before = simulator.simulate_attacks('localhost', after_remediation=False)
    successes_before = sum(r['success'] for r in results_before)
    print(f"Successful attacks: {successes_before}/{len(results_before)}")
    
    print("\n Attack Simulation (After Remediation) ")
    results_after = simulator.simulate_attacks('localhost', after_remediation=True)
    successes_after = sum(r['success'] for r in results_after)
    print(f"Successful attacks: {successes_after}/{len(results_after)}")
    
    print(f"\nRemediation effectiveness: {((successes_before - successes_after) / successes_before * 100):.1f}% reduction")
