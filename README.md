# CTEM vs Traditional Vulnerability Management

A controlled experimental framework comparing Continuous Threat Exposure Management (CTEM) against traditional vulnerability management approaches.

## Overview

This project empirically evaluates whether CTEM provides measurable improvements over traditional vulnerability management methodologies by simulating realistic threat scenarios on a vulnerable test environment.

### Research Objectives

Measure and compare the following key performance indicators (KPIs):

| Metric | Definition |
| **MEW** - Mean Exposure Window | Average time between vulnerability discovery and remediation |
| **MTTR** - Mean Time to Remediate | Average time to fix identified vulnerabilities |
| **CEC** - Critical Exposure Coverage | Percentage of critical vulnerabilities identified and prioritized |
| **RFR** - Remediation Focus Ratio | Focus on business-critical assets vs. all vulnerabilities |

### Workflow Comparison

- **CTEM Workflow**: Business context-aware prioritization based on asset criticality, threat intelligence, and exposure paths
- **Traditional Workflow**: Technical severity-based prioritization (CVSS scores only)

## System Architecture

### Vulnerable Services

Three containerised vulnerable services simulate a realistic attack surface:

```
┌─────────────────────────────────────────────────────────┐
│                   Docker Compose Network               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐   │
│  │    DVWA      │  │   MySQL     │  │ Node.js API  │   │
│  │  (Web App)   │  │ (Database)  │  │  (Backend)   │   │
│  │   :8080      │  │  :3306      │  │    :3000     │   │
│  └──────────────┘  └─────────────┘  └──────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
   - DVWA: Damn Vulnerable Web Application
   - MySQL: Database with test data
   - API: Intentionally vulnerable REST API
```

### Project Structure

```
ctem-trad-comparison/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── setup.sh                        # Setup script
├── docker/
│   ├── docker-compose.yml         # Container orchestration
│   ├── mysql-init/
│   │   └── init.sql               # Database initialization
│   └── vulnerable-api/            # Node.js vulnerable API
│       ├── Dockerfile
│       ├── package.json
│       └── server.js
├── data/                          # Experiment results (generated)
│   └── ctem_experiment.db         # SQLite results database
└── scripts/
    ├── run_experiment.py          # Main experiment orchestrator
    ├── attack_simulator.py        # Simulates attacker behavior
    ├── vulnerability_scanner.py   # Identifies vulnerabilities
    ├── ctem_context.py            # CTEM analysis context
    ├── pentesting_context.py      # Penetration testing context
    ├── vm_scanning_context.py     # Traditional VM scanning
    └── attack_surface_context.py  # Attack surface analysis
```

## Quick Start

### Prerequisites

- **Docker** & **Docker Compose** (for vulnerable services)
- **Python 3.8+** (for experiment scripts)
- **Git** (for version control)

### Installation & Setup

1. **Clone and navigate to the project:**
   ```bash
   cd ctem-trad-comparison
   ```

2. **Run the setup script:**
   ```bash
   ./setup.sh
   ```
   This verifies Docker, Python, and installs dependencies.

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### Running Experiments

#### Option 1: Full Experiment (with Docker)

```bash
python3 scripts/run_experiment.py
```

This will:
- Start vulnerable Docker containers
- Run multiple iterations of both workflows
- Collect metrics in real-time
- Export results to SQLite database

#### Option 2: Simulation Mode (no Docker required)

```bash
python3 scripts/run_experiment.py --simulation
```

Perfect for development and testing without Docker overhead.

## Data Collection

### Metrics Collected

The framework automatically collects:

- **Vulnerability Data**
  - Vulnerability ID, type, severity
  - CVSS score, affected service
  - Discovery timestamp, remediation timestamp

- **Workflow Performance**
  - Detection time (how long to identify vulnerability)
  - Prioritization decision (manual/automated)
  - Remediation time
  - Exposure window (time between discovery and fix)

- **Attack Simulation Results**
  - Which vulnerabilities were exploited
  - Success/failure of attacks
  - Attack path effectiveness

### Database Schema

Results are stored in SQLite with tables for:
- `exposures` - Vulnerability lifecycle data
- `attack_simulations` - Attack outcome records
- `metrics` - Calculated KPIs per iteration

## Analysis & Visualization

### Using Matplotlib for Results Analysis

After running experiments, visualize and analyze results using matplotlib:

```bash
python3 -c "
import sqlite3
import matplotlib.pyplot as plt
import pandas as pd

# Load results from database
conn = sqlite3.connect('data/ctem_experiment.db')
df = pd.read_sql_query('SELECT workflow_type, mew_seconds, mttr_seconds FROM exposures', conn)
conn.close()

# Create comparison visualizations
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

# Mean Exposure Window comparison
df.groupby('workflow_type')['mew_seconds'].mean().plot(kind='bar', ax=axes[0], color=['#FF6B6B', '#4ECDC4'])
axes[0].set_title('Mean Exposure Window (MEW)', fontsize=12, fontweight='bold')
axes[0].set_ylabel('Time (seconds)')
axes[0].set_xlabel('Workflow Type')

# Mean Time to Remediate comparison
df.groupby('workflow_type')['mttr_seconds'].mean().plot(kind='bar', ax=axes[1], color=['#FF6B6B', '#4ECDC4'])
axes[1].set_title('Mean Time to Remediate (MTTR)', fontsize=12, fontweight='bold')
axes[1].set_ylabel('Time (seconds)')
axes[1].set_xlabel('Workflow Type')

plt.tight_layout()
plt.savefig('results_comparison.png', dpi=300, bbox_inches='tight')
plt.show()
"
```

### Exporting Results

Query and export results for analysis:

```bash
# Export to CSV
sqlite3 -header -csv data/ctem_experiment.db \
  "SELECT workflow_type, AVG(mew_seconds) as avg_mew, AVG(mttr_seconds) as avg_mttr 
   FROM exposures GROUP BY workflow_type" > results_summary.csv

# Interactive database query
sqlite3 data/ctem_experiment.db
sqlite> SELECT workflow_type, AVG(mew_seconds) as avg_mew, 
               AVG(mttr_seconds) as avg_mttr FROM exposures GROUP BY workflow_type;
```

### Creating Custom Dashboards

Create comprehensive visualizations with matplotlib:

```python
import sqlite3
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

conn = sqlite3.connect('data/ctem_experiment.db')

# Load all metrics
exposures = pd.read_sql_query('SELECT * FROM exposures', conn)
attacks = pd.read_sql_query('SELECT * FROM attack_simulations', conn)
conn.close()

# Set style
sns.set_style("whitegrid")
fig = plt.figure(figsize=(16, 10))

# 1. MEW comparison
ax1 = plt.subplot(2, 3, 1)
exposures.groupby('workflow_type')['mew_seconds'].mean().plot(kind='bar', ax=ax1)
ax1.set_title('Mean Exposure Window', fontweight='bold')
ax1.set_ylabel('Seconds')

# 2. MTTR comparison
ax2 = plt.subplot(2, 3, 2)
exposures.groupby('workflow_type')['mttr_seconds'].mean().plot(kind='bar', ax=ax2)
ax2.set_title('Mean Time to Remediate', fontweight='bold')
ax2.set_ylabel('Seconds')

# 3. Critical exposure distribution
ax3 = plt.subplot(2, 3, 3)
exposure_by_severity = exposures.groupby(['workflow_type', 'severity']).size().unstack()
exposure_by_severity.plot(kind='bar', ax=ax3, stacked=True)
ax3.set_title('Exposures by Severity', fontweight='bold')
ax3.set_ylabel('Count')

# 4. Remediation status
ax4 = plt.subplot(2, 3, 4)
remediation_rates = exposures.groupby('workflow_type')['remediated'].apply(lambda x: (x.sum() / len(x)) * 100)
remediation_rates.plot(kind='bar', ax=ax4, color=['#FF6B6B', '#4ECDC4'])
ax4.set_title('Remediation Rate (%)', fontweight='bold')
ax4.set_ylabel('Percentage')

# 5. Attack success rate
ax5 = plt.subplot(2, 3, 5)
success_rates = attacks.groupby('workflow_type')['success'].apply(lambda x: (x.sum() / len(x)) * 100)
success_rates.plot(kind='bar', ax=ax5, color=['#FF6B6B', '#4ECDC4'])
ax5.set_title('Attack Success Rate (%)', fontweight='bold')
ax5.set_ylabel('Percentage')

# 6. Exposure timeline
ax6 = plt.subplot(2, 3, 6)
for workflow in exposures['workflow_type'].unique():
    data = exposures[exposures['workflow_type'] == workflow]
    ax6.scatter(data.index, data['mew_seconds'], label=workflow, alpha=0.6)
ax6.set_title('Exposure Window Timeline', fontweight='bold')
ax6.set_xlabel('Exposure Index')
ax6.set_ylabel('MEW (seconds)')
ax6.legend()

plt.tight_layout()
plt.savefig('analysis_dashboard.png', dpi=300, bbox_inches='tight')
plt.show()

print("Dashboard saved as analysis_dashboard.png")
```

## Workflow Details

### CTEM Workflow (`ctem_context.py`)

1. **Business Context Analysis**
   - Asset criticality mapping (CRITICAL → MEDIUM)
   - Threat intelligence correlation
   - Exposure classification (EXTERNAL/INTERNAL)

2. **Prioritization**
   - Combines technical severity + business impact
   - Focuses on attack paths, not all vulnerabilities
   - Considers threat landscape

3. **Remediation Focus**
   - Prioritizes business-critical systems
   - Targets actively exploited vulnerabilities
   - Reduces noise through context

### Traditional Workflow (`vm_scanning_context.py`)

1. **Vulnerability Scanning**
   - CVSS score-based severity ranking
   - No business context

2. **Prioritization**
   - Sort by technical severity only
   - All vulnerabilities treated equally

3. **Remediation**
   - Sequential fix by CVSS score
   - No threat intelligence consideration

## Expected Results

Poor performing traditional approach shows:
- **Higher MEW** - Longer exposure windows due to all-vulns-equal prioritization
- **Lower CEC** - Critical systems fixed later due to CVSS focus
- **Higher MTTR** - Wasted time on low-impact vulnerabilities

CTEM approach should demonstrate:
- **Lower MEW** - Business context reduces exposure time
- **Higher CEC** - Critical systems fixed first
- **Lower MTTR** - Focus on high-impact vulnerabilities

## Development & Testing

### Simulation Mode Features

The `--simulation` flag enables testing without Docker:
- Generates synthetic vulnerability data
- Simulates realistic attack patterns
- Produces valid output metrics

### Debug Mode

For development:
```bash
python3 scripts/run_experiment.py --debug
```

## Key Files Reference

| File | Purpose |
|------|---------|
| [run_experiment.py](scripts/run_experiment.py) | Main orchestrator, database setup |
| [ctem_context.py](scripts/ctem_context.py) | CTEM-specific analysis logic |
| [vm_scanning_context.py](scripts/vm_scanning_context.py) | Traditional VM scanning logic |
| [attack_simulator.py](scripts/attack_simulator.py) | Simulates attack scenarios |
| [vulnerability_scanner.py](scripts/vulnerability_scanner.py) | Identifies vulnerabilities |

## Configuration

### Docker Services Configuration

Edit [docker/docker-compose.yml](docker/docker-compose.yml) to:
- Change port mappings
- Adjust resource limits
- Add additional vulnerable services
- Modify environment variables

### Database Configuration

Edit [docker/mysql-init/init.sql](docker/mysql-init/init.sql) to customize the database schema and test data.

## Contributing

To extend this framework:

1. **Add new attack simulations**: Modify `attack_simulator.py`
2. **Add new metrics**: Extend database schema in `run_experiment.py`
3. **Add new workflows**: Create new context analyzer (e.g., `ai_context.py`)
4. **Add new visualizations**: Create matplotlib-based analysis scripts in a new `analysis/` folder

## License

Academic research project - Coventry University ComSci Year 3

## Troubleshooting

### Docker Issues
- Ensure Docker daemon is running
- Check port availability (8080, 3000, 3306)
- Run `docker-compose logs` for service errors

### Python Issues
- Use Python 3.8+: `python3 --version`
- Install dependencies: `pip install -r requirements.txt`
- Use simulation mode if Docker unavailable: `--simulation`

### Database Issues
- Remove existing database: `rm data/ctem_experiment.db`
- Re-run setup to recreate schema

### Visualization Issues
- Ensure matplotlib is installed: `pip install matplotlib seaborn`
- Export plots as PNG: `plt.savefig('filename.png', dpi=300)`
- Use SSH with X11 forwarding for remote servers: `ssh -X user@host`

## Contact

For questions about the experimental framework or methodology, refer to the project documentation or repository issues or contact me via the links at www.xynox19.github.io !
