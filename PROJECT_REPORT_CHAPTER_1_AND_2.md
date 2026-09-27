# Project Report: AI-Powered CSPM & Intelligent Risk Analysis Platform
## Subsystem Report: Student 1 (Data Engineering & Cloud Misconfiguration Rule Engine)

---

# CHAPTER 1: Executive Summary, Problem Statement & System Architecture

## 1.1 Executive Summary
Cloud Security Posture Management (CSPM) is a critical pillar of modern cloud infrastructure defense. As enterprises scale their multicloud environments, manual inspection of thousands of Identity and Access Management (IAM) configurations, Object Storage Access Control Lists (ACLs), Security Group Ingress rules, and activity logs becomes intractable.

This project delivers an autonomous, reproducible, and verifiable **Data Engineering & Cloud Misconfiguration Rule Engine** serving as the foundational tier (Modules 1, 2, and 3) of the overarching *AI-Powered CSPM and Intelligent Risk Analysis Platform*.

Without standardizing, validating, and normalizing raw cloud state, downstream machine learning models (Behavior/Log Anomaly Detection - Student 2) and Large Language Model (LLM) agents and interactive dashboards (Student 3) cannot reliably operate. This module establishes a deterministic, auditable policy-as-code evaluation engine that translates complex cloud configurations into actionable, structured security findings.

## 1.2 Problem Statement & Constraints
Building and evaluating CSPM platforms in educational or prototyping contexts presents major challenges:
1. **Cloud Cost & Billing Barriers**: Connecting live AWS enterprise environments requires credit cards, active subscriptions, and exposes users to unintended billing liabilities or infrastructure drift.
2. **Ground Truth Scarcity**: Real production cloud environments rarely possess tagged, well-labeled misconfigurations with ground truth needed to scientifically evaluate detection accuracy and false positive rates.
3. **Schema Heterogeneity**: Cloud APIs emit disparately structured JSON objects, varying timestamp serializations, nested access policies, and optional fields that break downstream ML parsers if not strictly normalized.

## 1.3 Solution & Module Ownership
To resolve these constraints without incurring cloud charges or exposing credentials:
- **Module 1 (Simulated Cloud Data Sources)**: Implements synthetic data generators using `Faker` and deterministic random seeds to generate high-fidelity AWS configurations (IAM, S3, EC2, VPC, CloudTrail, Software Packages). Injected vulnerabilities mirror real-world attack vectors (e.g., open SSH 0.0.0.0/0, wildcard administrator privileges, missing MFA, and unencrypted storage).
- **Module 2 (Data Collection & Processing Layer)**: Provides an automated Extract, Transform, and Load (ETL) pipeline (`data_loader.py` and `normalizer.py`) that enforces uniform ARNs, ISO 8601 UTC timestamps, missing-value imputation, and flattens deeply nested JSON policies.
- **Module 3 (Security Analysis - Rule-Based Engine)**: Codifies industry-standard CIS AWS Benchmark controls into modular policy-as-code scanners producing standardized findings according to a strict inter-student data contract.

---

# CHAPTER 2: Technical Design, Simulation Methodology & Policy Engine

## 2.1 Module 1: Cloud Data Simulation Methodology
The data generator (`src/generators/generate_mock_cloud_data.py`) produces realistic AWS resources:

| Resource Type | Count | Injected Misconfigurations & Real-world Characteristics |
| :--- | :--- | :--- |
| **IAM Users & Roles** | 50 | Root/admin users missing MFA, `AdministratorAccess` wildcard permissions (`*` on `*`), accounts inactive >90 days, active access keys. |
| **S3 Storage Buckets** | 30 | Public read/write ACL grants (`AllUsers`), disabled Public Access Block (PAB), unencrypted buckets missing AWS KMS/AES-256, versioning disabled. |
| **EC2 Compute Instances**| 40 | Security groups with unrestricted ingress (`0.0.0.0/0`) on port 22 (SSH), port 3389 (RDP), port 8080 (Proxy/Web), outdated AMIs (>365 days old). |
| **VPC Networks** | 5 | Multi-AZ subnets (Public/Private), CIDR blocks, route tables, and Internet Gateways. |
| **CloudTrail Activity** | 1,050 | Rich event streams (`ConsoleLogin`, `PutBucketAcl`, `AuthorizeSecurityGroupIngress`, `RunInstances`) with user agents, IPs, and authorization failures. |
| **Software Inventory** | 159 | Installed packages (OpenSSH, Nginx, Apache2, Log4j, Sudo) cross-referenced with known CVE identifiers (e.g., CVE-2021-44228, CVE-2021-41773). |

## 2.2 Module 2: Ingestion & Normalization Pipeline (ETL)
The ETL layer reads heterogeneous data and unifies it into `/data/processed/cloud_inventory.json`:
1. **Timestamp Normalization**: All varied time representations are parsed into ISO 8601 UTC strings (`YYYY-MM-DDTHH:MM:SSZ`), allowing chronological sequence ordering in log analyzers.
2. **Identifier Standardization**: Canonical AWS Resource Names (ARNs) and 12-digit account IDs are enforced across all entities.
3. **Policy Parsing & Flattening**: Complex IAM JSON statements and Security Group ingress rules are parsed into flattened boolean flags (`has_admin_policy`, `has_wildcard_permission`, `internet_exposed_ports`).
4. **Missing Value Imputation**: Null IP addresses, empty tag structures, and absent encryption parameters are defensively converted into consistent representations preventing runtime null-pointer exceptions in downstream ML models.

## 2.3 Module 3: Rule-Based Security Engine
Security rules align with the CIS AWS Foundations Benchmark:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        RULE ENGINE TAXONOMY                            │
├─────────────────┬──────────────────────┬──────────┬────────────────────┤
│ Rule ID         │ Rule Name            │ Severity │ Benchmark / Control│
├─────────────────┼──────────────────────┼──────────┼────────────────────┤
│ RULE-IAM-001    │ Admin Missing MFA    │ CRITICAL │ CIS AWS 1.5 & 1.10 │
│ RULE-IAM-002    │ Wildcard Admin Perms │ HIGH     │ CIS AWS 1.16       │
│ RULE-IAM-003    │ Inactive Credentials │ MEDIUM   │ CIS AWS 1.3        │
│ RULE-S3-001     │ Public S3 Bucket     │ HIGH/CRIT│ CIS AWS 2.1.5      │
│ RULE-S3-002     │ Missing Encryption   │ MEDIUM   │ CIS AWS 2.1.1      │
│ RULE-S3-003     │ Disabled Versioning  │ LOW      │ CIS AWS 2.1.3      │
│ RULE-NET-001    │ Public SSH Port 22   │ CRITICAL │ CIS AWS 5.2        │
│ RULE-NET-002    │ Public RDP Port 3389 │ CRITICAL │ CIS AWS 5.3        │
│ RULE-NET-003    │ Public Port 8080     │ HIGH     │ Well-Architected   │
│ RULE-COMP-001   │ Outdated Base AMI    │ MEDIUM   │ CIS AWS Compute    │
│ RULE-COMP-002   │ Host Vulnerable CVE  │ HIGH/CRIT│ Vulnerability Mgmt │
└─────────────────┴──────────────────────┴──────────┴────────────────────┘
```

## 2.4 Data Contract Schema
To ensure interoperability with Student 2 (Risk Engine) and Student 3 (UI Dashboard), every finding produced in `rule_findings.json` satisfies the JSON contract:

```json
{
  "finding_id": "string",
  "resource_type": "string (e.g. IAM_USER, S3_BUCKET, EC2_INSTANCE)",
  "resource_id": "string (ARN or ID)",
  "category": "string (IAM Security, Storage Security, Network Security, Compute Security)",
  "rule_name": "string",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "description": "string (Human-readable finding rationale)",
  "raw_config": "object (Contextual parameters for ML / UI display)",
  "timestamp": "ISO 8601 UTC timestamp"
}
```

## 2.5 Verification & Empirical Results
A 13-test automated `pytest` suite confirms:
- **100% Injected Misconfiguration Detection**: Every intentionally insecure resource (public S3 bucket, unencrypted bucket, non-MFA user, wildcard admin, open port 22/3389/8080, outdated AMI) was identified without failure.
- **Contract Conformance**: Zero schema violations across 127 total detected findings.
- **Execution Performance**: Full ingestion, normalization, and evaluation runs in under 2 seconds on standard commodity hardware.
