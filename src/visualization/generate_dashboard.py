"""
Interactive Visual Dashboard Generator for Student 1 CSPM Deliverables.
Generates a standalone, beautiful HTML dashboard to view the normalized cloud inventory
and rule findings directly in any web browser without needing external dependencies.
"""

import os
import json
import webbrowser
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

def generate_html_dashboard(inventory_path: str, findings_path: str, output_html_path: str):
    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory = json.load(f)
    with open(findings_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    # Calculate statistics
    total_findings = len(findings)
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    counts = inventory.get("metadata", {}).get("counts", {})
    total_resources = inventory.get("metadata", {}).get("total_resources", 0)

    # Encode findings to JSON string safely for embedded JS
    findings_json_str = json.dumps(findings)
    inventory_summary_json = json.dumps(counts)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI-Powered CSPM Platform | Student 1 Dashboard</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --success: #10b981;
      --accent: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text-main); padding: 24px; }}
    .container {{ max-width: 1400px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--card-border); }}
    .badge-sub {{ background: #312e81; color: #a5b4fc; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
    h1 {{ font-size: 26px; font-weight: 700; margin-top: 4px; }}
    p.subtitle {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
    
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 18px; }}
    .stat-label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
    .stat-value {{ font-size: 32px; font-weight: 800; margin-top: 8px; }}
    
    .critical-color {{ color: var(--critical); }}
    .high-color {{ color: var(--high); }}
    .medium-color {{ color: var(--medium); }}
    .low-color {{ color: var(--low); }}
    .accent-color {{ color: var(--accent); }}
    .success-color {{ color: var(--success); }}

    .inventory-section {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; margin-bottom: 24px; }}
    .inv-pills {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 12px; }}
    .inv-pill {{ background: #0f172a; border: 1px solid var(--card-border); border-radius: 8px; padding: 10px 16px; display: flex; align-items: center; gap: 10px; }}
    .inv-pill strong {{ font-size: 18px; color: #38bdf8; }}

    .findings-section {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; }}
    .controls-row {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px; }}
    .search-box {{ background: #0f172a; border: 1px solid var(--card-border); color: #fff; padding: 10px 16px; border-radius: 8px; width: 320px; font-size: 14px; outline: none; }}
    .filter-btn-group {{ display: flex; gap: 8px; }}
    .filter-btn {{ background: #0f172a; border: 1px solid var(--card-border); color: var(--text-muted); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }}
    .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}

    table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 14px; }}
    th {{ text-align: left; padding: 12px; background: #0f172a; color: var(--text-muted); font-size: 12px; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid var(--card-border); }}
    td {{ padding: 12px; border-bottom: 1px solid #293548; vertical-align: middle; }}
    tr:hover {{ background: #263349; }}
    
    .sev-tag {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    .sev-CRITICAL {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
    .sev-HIGH {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
    .sev-MEDIUM {{ background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid #eab308; }}
    .sev-LOW {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid #3b82f6; }}
    
    .code-tag {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #cbd5e1; word-break: break-all; }}
    .contract-note {{ margin-top: 24px; padding: 16px; background: #1e1b4b; border: 1px solid #4338ca; border-radius: 8px; font-size: 13px; color: #c7d2fe; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <span class="badge-sub">Enterprise Security Posture</span>
        <span class="badge-sub" style="background: #065f46; color: #a7f3d0; margin-left: 8px;">CISA KEV Threat Intel Active</span>
        <h1>AI-Powered CSPM Security Posture Dashboard</h1>
        <p class="subtitle">Unified Cloud Asset Inventory & Policy-as-Code Security Findings</p>
      </div>
      <div>
        <span style="font-size: 13px; color: var(--text-muted);">Account ID: <strong>123456789012</strong> (AWS Production)</span>
      </div>
    </header>

    <!-- Top Statistics Cards -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Cloud Resources</div>
        <div class="stat-value accent-color">{total_resources}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Security Findings</div>
        <div class="stat-value">{total_findings}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical Severity</div>
        <div class="stat-value critical-color">{crit_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">High Severity</div>
        <div class="stat-value high-color">{high_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Medium Severity</div>
        <div class="stat-value medium-color">{med_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Low Severity</div>
        <div class="stat-value low-color">{low_count}</div>
      </div>
    </div>

    <!-- Normalized Inventory Breakdown -->
    <div class="inventory-section">
      <h2 style="font-size: 18px; margin-bottom: 4px;">Normalized Inventory Overview</h2>
      <p style="color: var(--text-muted); font-size: 13px;">Standardized into canonical ARNs, ISO 8601 UTC timestamps, and flattened policies:</p>
      <div class="inv-pills">
        <div class="inv-pill"><span>IAM Users:</span> <strong>{counts.get('iam_users', 0)}</strong></div>
        <div class="inv-pill"><span>IAM Roles:</span> <strong>{counts.get('iam_roles', 0)}</strong></div>
        <div class="inv-pill"><span>S3 Buckets:</span> <strong>{counts.get('s3_buckets', 0)}</strong></div>
        <div class="inv-pill"><span>EC2 Instances:</span> <strong>{counts.get('ec2_instances', 0)}</strong></div>
        <div class="inv-pill"><span>VPC Networks:</span> <strong>{counts.get('vpcs', 0)}</strong></div>
        <div class="inv-pill"><span>CloudTrail Logs:</span> <strong>{counts.get('cloudtrail_events', 0)}</strong></div>
      </div>
    </div>

    <!-- Security Findings Table -->
    <div class="findings-section">
      <div class="controls-row">
        <div>
          <h2 style="font-size: 18px;">Security Findings & CIS Benchmarks</h2>
          <p style="color: var(--text-muted); font-size: 13px;">Automated policy-as-code evaluations mapped to CIS AWS Foundations Benchmarks</p>
        </div>
        <div style="display: flex; gap: 12px;">
          <input type="text" id="searchInput" class="search-box" placeholder="Search rules, resources, ARNs..." onkeyup="filterFindings()">
          <div class="filter-btn-group">
            <button class="filter-btn active" onclick="setSeverityFilter('ALL', this)">All</button>
            <button class="filter-btn" onclick="setSeverityFilter('CRITICAL', this)">Critical ({crit_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('HIGH', this)">High ({high_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('MEDIUM', this)">Medium ({med_count})</button>
            <button class="filter-btn" onclick="setSeverityFilter('LOW', this)">Low ({low_count})</button>
          </div>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th style="width: 140px;">Rule ID</th>
            <th style="width: 110px;">Severity</th>
            <th style="width: 150px;">Category</th>
            <th>Rule Name & Description</th>
            <th>Resource Identifier (ARN / ID)</th>
          </tr>
        </thead>
        <tbody id="findingsBody">
          <!-- Populated by JavaScript -->
        </tbody>
      </table>
    </div>

    <div class="contract-note">
      <strong>Automated Export Pipeline:</strong> Standardized security findings and unified cloud inventory are exported to <code>data/processed/</code>, ready for risk scoring analysis, SIEM ingestion, and automated remediation workflows.
    </div>
  </div>

  <script>
    const allFindings = {findings_json_str};
    let currentSeverity = 'ALL';

    function renderTable(data) {{
      const tbody = document.getElementById('findingsBody');
      tbody.innerHTML = '';
      if (data.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 24px; color: #94a3b8;">No matching findings found.</td></tr>';
        return;
      }}

      data.forEach(item => {{
        const row = document.createElement('tr');
        row.innerHTML = `
          <td><span class="code-tag">${{item.finding_id}}</span></td>
          <td><span class="sev-tag sev-${{item.severity}}">${{item.severity}}</span></td>
          <td><span style="font-weight: 600; color: #cbd5e1;">${{item.category}}</span></td>
          <td>
            <div style="font-weight: 700; color: #f8fafc; margin-bottom: 2px;">${{item.rule_name}}</div>
            <div style="color: #94a3b8; font-size: 13px;">${{item.description}}</div>
          </td>
          <td><span class="code-tag">${{item.resource_id}}</span></td>
        `;
        tbody.appendChild(row);
      }});
    }}

    function filterFindings() {{
      const query = document.getElementById('searchInput').value.toLowerCase();
      const filtered = allFindings.filter(f => {{
        const matchesSev = (currentSeverity === 'ALL' || f.severity === currentSeverity);
        const matchesQuery = (
          f.finding_id.toLowerCase().includes(query) ||
          f.rule_name.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query) ||
          f.resource_id.toLowerCase().includes(query) ||
          f.category.toLowerCase().includes(query)
        );
        return matchesSev && matchesQuery;
      }});
      renderTable(filtered);
    }}

    function setSeverityFilter(sev, btn) {{
      currentSeverity = sev;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterFindings();
    }}

    // Initial render
    renderTable(allFindings);
  </script>
</body>
</html>
"""
    os.makedirs(os.path.dirname(output_html_path), exist_ok=True)
    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_html_path

if __name__ == "__main__":
    inv_file = os.path.join(PROJECT_ROOT, "data", "processed", "cloud_inventory.json")
    find_file = os.path.join(PROJECT_ROOT, "data", "processed", "rule_findings.json")
    out_html = os.path.join(PROJECT_ROOT, "data", "processed", "security_dashboard.html")

    generated_path = generate_html_dashboard(inv_file, find_file, out_html)
    print(f"Interactive Dashboard HTML generated at: {generated_path}")
