# AI-Powered Cloud Security Posture Management (CSPM) Platform
## Student 1: Data Engineering & Cloud Misconfiguration Rule Engine

> **Role**: Data & Rule Engine Lead  
> **Owned Modules**: Module 1 (Simulated Cloud Data Sources), Module 2 (Data Collection & Processing Layer), Module 3 (Security Analysis - Rule-Based Engine)  
> **Stack**: Python, Pandas, Faker, PyYAML, Pytest  
> **Key Deliverables**: Normalized Cloud Inventory (`cloud_inventory.json`) and Policy-as-Code Rule Findings (`rule_findings.json`)  
> **Zero Cloud Cost**: Runs 100% locally with high-fidelity AWS-like realistic data. **No AWS account, no credit card, and no cloud fees required.**

---

## 1. Executive Summary & Modules Overview

This subsystem is the bedrock of the entire AI-Powered CSPM system. Without accurate, standardized simulated cloud data and deterministic rule-based checks, neither the ML models (Student 2) nor the LLM/UI (Student 3) can function.

```
+---------------------------------------------------------------------------------------------------+
|                                  STUDENT 1 SUBSYSTEM ARCHITECTURE                                 |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  [ Module 1: Simulated AWS Data Sources ]                                                         |
|  - 50 IAM Users & Roles (Admins, Devs, Service Accounts with Injected MFA & Wildcard Perms)       |
|  - 30 S3 Buckets (Public ACLs, Bucket Policies, Unencrypted Buckets, Missing Versioning)          |
|  - 40 EC2 Instances (Security Groups open to 0.0.0.0/0 on 22/3389/8080, Outdated AMIs)           |
|  - 5 VPC Networks (Subnets, CIDR Blocks, Internet Gateways)                                       |
|  - 1,000+ CloudTrail JSON Logs (Logins, Ingress changes, AccessDenied errors, Foreign IPs)        |
|  - Software Inventory CSV (Installed Packages, Versions, CVE Tags)                                |
|                                       │                                                           |
|                                       ▼                                                           |
|  [ Module 2: Data Collection & Processing (ETL) ]                                                 |
|  - data_loader.py : Ingests JSON/CSV raw files with schema validation                             |
|  - normalizer.py  : Standardizes ARNs, ISO 8601 timestamps, flattens policies and port rules      |
|  - Output         : data/processed/cloud_inventory.json                                           |
|                                       │                                                           |
|                                       ▼                                                           |
|  [ Module 3: Policy-As-Code Security Rule Engine ]                                                |
|  - rule_iam_mfa()        : Flags active users & admins without MFA (CIS AWS 1.5, 1.10)            |
|  - rule_iam_admin()      : Detects wildcard AdministratorAccess policies (CIS AWS 1.16)           |
|  - rule_s3_public()      : Flags public read/write ACLs & missing encryption (CIS AWS 2.1.1, 2.1.5)|
|  - rule_ec2_ingress()    : Scans Security Groups for 0.0.0.0/0 on 22, 3389, 8080 (CIS AWS 5.2,5.3)|
|  - rule_ec2_outdated_ami(): Detects base images older than 365 days                                |
|  - Output         : data/processed/rule_findings.json                                             |
|                                       │                                                           |
|                                       ▼                                                           |
|  [ Inter-Student Data Contract Hand-off ]                                                         |
|  --> Student 2: Behavior / ML Anomaly Detection & Risk Scoring Engine                             |
|  --> Student 3: Streamlit Interactive Security Dashboard & LLM Remediation Agent                  |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Directory Structure

```text
ai_cspm_data_engine/
├── data/
│   ├── raw/                              # Ingested simulated cloud datasets
│   │   ├── iam_users_roles.json          # 50 IAM entities
│   │   ├── s3_buckets.json               # 30 S3 buckets
│   │   ├── ec2_instances.json            # 40 EC2 instances
│   │   ├── vpc_networks.json             # 5 VPC networks
│   │   ├── cloudtrail_events.json        # 1,000+ CloudTrail events
│   │   └── software_inventory.csv        # Host package & CVE inventory
│   └── processed/                        # Output contracts for Student 2 & 3
│       ├── cloud_inventory.json          # Normalized unified inventory
│       └── rule_findings.json            # Standardized security findings
├── schemas/                              # Formal JSON schemas
│   ├── iam_schema.json
│   ├── s3_schema.json
│   ├── ec2_schema.json
│   ├── cloudtrail_schema.json
│   └── rule_findings_schema.json
├── src/
│   ├── generators/
│   │   └── generate_mock_cloud_data.py   # Faker-based synthetic data generator
│   ├── ingestion/
│   │   ├── data_loader.py                # Raw ingestion layer
│   │   └── normalizer.py                 # Schema standardization & ETL
│   └── rules/
│       ├── base_rule.py                  # Base rule class & finding builder
│       ├── iam_rules.py                  # CIS IAM checks (MFA, Admin wildcard, Inactivity)
│       ├── s3_rules.py                   # CIS S3 checks (Public access, Encryption, Versioning)
│       ├── ec2_rules.py                  # CIS EC2/Network checks (SSH 22, RDP 3389, Port 8080, AMIs)
│       └── scanner.py                    # Scanner engine orchestrator
├── tests/
│   ├── test_generators.py                # Asserts dataset counts and schemas
│   ├── test_normalizer.py                # Asserts ETL transformation & null handling
│   └── test_rules.py                     # Asserts 100% detection of injected misconfigurations
├── run_pipeline.py                       # Single command entrypoint
├── requirements.txt                      # Project dependencies
└── README.md
```

---

## 3. Quick Start (How to Run Everything)

### Step 1: Activate Virtual Environment
```powershell
# From the project directory:
.\.venv\Scripts\Activate.ps1
```

### Step 2: Run the Complete Pipeline
Run the single-command orchestrator to ingest, normalize, and scan all resources:
```powershell
python run_pipeline.py
```
*(To re-generate brand new synthetic datasets at any time, run: `python run_pipeline.py --generate`)*

### Step 3: View the Interactive Visual Dashboard in Your Browser
Launch the visual web dashboard to see and search all 127 findings, severity breakdowns, and inventory:
```powershell
python view_dashboard.py
```
*(Or simply double-click `data/processed/security_dashboard.html` in File Explorer!)*

### Step 4: Run the Pytest Test Suite
Verify that **100% of injected misconfigurations are flagged** and the data contract conforms to specifications:
```powershell
pytest -v
```

---

## 4. Student 2 & 3 Data Contract Interface

The output in `data/processed/rule_findings.json` strictly satisfies the team data contract:

```json
[
  {
    "finding_id": "RULE-IAM-001_admin_dev",
    "resource_type": "IAM_USER",
    "resource_id": "arn:aws:iam::123456789012:user/admin_dev",
    "category": "IAM Security",
    "rule_name": "Root or Admin User Missing MFA",
    "severity": "CRITICAL",
    "description": "User admin_dev has AdministratorAccess policy attached but Multi-Factor Authentication is disabled.",
    "raw_config": {
      "mfa_active": false,
      "attached_policies": ["AdministratorAccess"],
      "has_admin_policy": true
    },
    "timestamp": "2026-09-26T09:19:51Z"
  },
  {
    "finding_id": "RULE-NET-001_i-2931a4c4555e1db7_port22",
    "resource_type": "EC2_INSTANCE",
    "resource_id": "i-2931a4c4555e1db7",
    "category": "Network Security",
    "rule_name": "Public SSH Port Open to Internet",
    "severity": "CRITICAL",
    "description": "Security group sg-bastion allows inbound TCP port 22 from CIDR 0.0.0.0/0 on instance 'web-bastion-ssh-public'.",
    "raw_config": {
      "public_ip": "54.210.12.8",
      "open_ports": [22, 443],
      "security_group_id": "sg-bastion",
      "port": 22
    },
    "timestamp": "2026-09-26T09:19:51Z"
  }
]
```
