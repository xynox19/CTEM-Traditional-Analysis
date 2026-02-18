# CTEM vs Traditional Vulnerability Management

Comparison of Continuous Threat Exposure Management against traditional vulnerability management approaches.

## Overview

Controlled experimental framework testing whether CTEM provides measurable improvements in:
- Mean Exposure Window (MEW)
- Mean Time to Remediate (MTTR)
- Critical Exposure Coverage (CEC)
- Remediation Focus Ratio (RFR)

Will be compared to other methodologies such as :

FILL IN HERE

## Setup

```bash
./setup.sh
python3 scripts/run_experiment.py
```

## Environment

Three vulnerable services in Docker:
- DVWA (web app)
- MySQL (database)
- Node.js API

## Metrics

Automated collection of timestamps and attack simulation results. Exports to CSV for analysis.
Will be demonstrated and applied in PowerBI for artefact (including code etc.)