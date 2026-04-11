"""
AI-SOC Security Report HTML generator.

This module transforms raw alert data into SOC-style intelligence reporting HTML.
All dynamic content is escaped via html.escape before being rendered.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import html
import re
from typing import Any


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 7:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _score_from_severity(severity: str) -> float:
    return {
        "critical": 9.1,
        "high": 8.0,
        "medium": 5.9,
        "low": 3.1,
    }.get(severity, 3.1)


def _guess_cwe(title: str, description: str) -> str:
    text = f"{title} {description}".lower()
    rules = [
        (("xss", "cross-site scripting"), "CWE-79"),
        (("sql injection", "sqli"), "CWE-89"),
        (("ssrf", "server side request forgery"), "CWE-918"),
        (("authentication failed", "brute force", "login failed"), "CWE-307"),
        (("command injection", "rce"), "CWE-78"),
        (("path traversal", "../"), "CWE-22"),
        (("insecure direct object reference", "idor"), "CWE-639"),
        (("csrf",), "CWE-352"),
    ]
    for keywords, cwe in rules:
        if any(k in text for k in keywords):
            return cwe
    return "CWE-20"


def _category_from_title(title: str, description: str) -> str:
    text = f"{title} {description}".lower()
    if "xss" in text:
        return "xss"
    if "ssrf" in text:
        return "ssrf"
    if any(k in text for k in ("auth", "login", "brute force", "credential")):
        return "authentication"
    if any(k in text for k in ("sql injection", "sqli", "command injection", "path traversal")):
        return "input_validation"
    return "general"


def _safe_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    return value


def _extract_vuln_snippet(alert: dict) -> str:
    location = alert.get("location") or ""
    full_log = alert.get("full_log") or ""
    if location and full_log:
        return f"location={location}\n{full_log[:260]}"
    if full_log:
        return full_log[:260]
    return "No direct source snippet available from this event."


def _extract_poc(alert: dict) -> str:
    src = alert.get("data", {}).get("src_ip") or alert.get("agent", {}).get("ip") or "unknown"
    dst = alert.get("data", {}).get("dest_ip") or "unknown"
    rid = alert.get("rule", {}).get("id") or "n/a"
    ts = _safe_timestamp(alert.get("@timestamp"))
    return f"Detected event: src={src}, dst={dst}, rule_id={rid}, timestamp={ts}"


def _fix_by_category(category: str, severity: str) -> str:
    base = {
        "xss": "Apply output encoding, strict CSP, and sanitize untrusted input before rendering.",
        "ssrf": "Restrict outbound requests, enforce allowlists, and block access to metadata/internal ranges.",
        "authentication": "Enable MFA, lockout and rate-limit controls, and strengthen credential policy.",
        "input_validation": "Validate input server-side with strict schema, parameterized queries, and reject unsafe payloads.",
        "general": "Harden service configuration, improve detection rules, and enforce least privilege.",
    }.get(category, "Harden controls and enforce secure defaults.")
    if severity in ("critical", "high"):
        return f"{base} Patch immediately and validate with retest within 24-72h."
    return f"{base} Schedule remediation and verify during next security sprint."


def normalize_findings(
    wazuh_alerts: list[dict] | None,
    suricata_alerts: list[dict] | None,
    ai_alerts: list[dict] | None,
) -> list[dict]:
    wazuh_alerts = wazuh_alerts or []
    suricata_alerts = suricata_alerts or []
    ai_alerts = ai_alerts or []

    raw: list[dict] = []
    for a in wazuh_alerts:
        level = _to_int(a.get("rule", {}).get("level"), 1)
        title = a.get("rule", {}).get("description") or "Wazuh alert"
        raw.append(
            {
                "source": "wazuh",
                "level": level,
                "severity": _severity_from_level(level),
                "title": title,
                "description": f"Wazuh detected policy/security event: {title}",
                "timestamp": _safe_timestamp(a.get("@timestamp")),
                "rule_id": str(a.get("rule", {}).get("id") or ""),
                "src_ip": a.get("data", {}).get("src_ip") or a.get("agent", {}).get("ip") or "",
                "dest_ip": a.get("data", {}).get("dest_ip") or "",
                "agent": a.get("agent", {}).get("name") or "",
                "evidence": _extract_poc(a),
                "code": _extract_vuln_snippet(a),
            }
        )

    for a in suricata_alerts:
        s = _to_int(a.get("data", {}).get("alert", {}).get("severity"), 3)
        level = max(1, (4 - max(1, min(s, 3))) * 4)
        title = a.get("data", {}).get("alert", {}).get("signature") or "Suricata IDS alert"
        raw.append(
            {
                "source": "suricata",
                "level": level,
                "severity": _severity_from_level(level),
                "title": title,
                "description": f"Suricata detected network-level suspicious traffic: {title}",
                "timestamp": _safe_timestamp(a.get("@timestamp")),
                "rule_id": str(a.get("data", {}).get("alert", {}).get("signature_id") or ""),
                "src_ip": a.get("data", {}).get("src_ip") or "",
                "dest_ip": a.get("data", {}).get("dest_ip") or "",
                "agent": "Suricata",
                "evidence": _extract_poc(a),
                "code": _extract_vuln_snippet(a),
            }
        )

    for a in ai_alerts:
        risk = float(a.get("risk_score") or 0.0)
        severity = "critical" if risk >= 0.9 else "high" if risk >= 0.75 else "medium" if risk >= 0.5 else "low"
        level = 12 if severity == "critical" else 9 if severity == "high" else 5 if severity == "medium" else 2
        models = ", ".join(a.get("triggered_models") or [])
        title = f"AI anomaly score={risk:.3f}"
        raw.append(
            {
                "source": "ai",
                "level": level,
                "severity": severity,
                "title": title,
                "description": f"AI engine flagged suspicious behavior from source IP using models: {models or 'n/a'}",
                "timestamp": _safe_timestamp(a.get("@timestamp")),
                "rule_id": "AI",
                "src_ip": a.get("src_ip") or "",
                "dest_ip": "",
                "agent": "AI Engine",
                "evidence": f"risk_score={risk:.3f}, should_block={bool(a.get('should_block'))}, models={models or 'n/a'}",
                "code": "Feature-based anomaly detection (IsolationForest/EWMA/CUSUM).",
            }
        )

    dedup: dict[str, dict] = {}
    for item in raw:
        category = _category_from_title(item["title"], item["description"])
        cwe = _guess_cwe(item["title"], item["description"])
        cvss = _score_from_severity(item["severity"])
        key = f"{item['source']}|{item['rule_id']}|{item['title'].lower()}|{item['src_ip']}"
        enriched = {
            **item,
            "category": category,
            "cwe": cwe,
            "cvss": cvss,
            "impact_confidentiality": "High" if item["severity"] in ("critical", "high") else "Medium",
            "impact_integrity": "High" if item["severity"] in ("critical", "high") else "Medium",
            "impact_availability": "Medium" if item["severity"] in ("critical", "high", "medium") else "Low",
            "fix": _fix_by_category(category, item["severity"]),
            "count": 1,
        }
        if key not in dedup:
            dedup[key] = enriched
            continue
        old = dedup[key]
        old["count"] += 1
        if SEVERITY_ORDER[enriched["severity"]] > SEVERITY_ORDER[old["severity"]]:
            dedup[key] = {**old, **enriched, "count": old["count"]}

    findings = list(dedup.values())
    findings.sort(key=lambda x: (SEVERITY_ORDER[x["severity"]], x["cvss"]), reverse=True)

    # Assign IDs by severity class (C1/H1/M1/L1)
    seq = defaultdict(int)
    for f in findings:
        prefix = {"critical": "C", "high": "H", "medium": "M", "low": "L"}[f["severity"]]
        seq[prefix] += 1
        f["finding_id"] = f"{prefix}{seq[prefix]}"
    return findings


def _derive_control_status(findings: list[dict]) -> list[dict]:
    by_category: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        by_category[f.get("category", "general")].append(f.get("severity", "low"))

    def status_for(cat: str) -> str:
        sev = by_category.get(cat, [])
        if any(s in ("critical", "high") for s in sev):
            return "fail"
        if any(s in ("medium", "low") for s in sev):
            return "warn"
        return "pass"

    return [
        {"name": "Input Validation", "status": status_for("input_validation")},
        {"name": "Authentication", "status": status_for("authentication")},
        {"name": "XSS", "status": status_for("xss")},
        {"name": "SSRF", "status": status_for("ssrf")},
    ]


def _risk_score(counts: Counter) -> int:
    raw = counts["critical"] * 20 + counts["high"] * 8 + counts["medium"] * 3 + counts["low"] * 1
    return max(0, min(100, raw))


def _threat_model_rows(findings: list[dict]) -> list[dict]:
    rows = []
    for f in findings[:30]:
        cat = f.get("category", "general")
        if cat == "xss":
            actor, vector, asset = "Rogue external actor", "Injected client-side payload", "SOC analyst browser session"
        elif cat == "ssrf":
            actor, vector, asset = "Internal pivot attacker", "Server-side request pivot", "Internal services and metadata"
        elif cat == "authentication":
            actor, vector, asset = "Credential attacker", "Brute force / auth abuse", "Accounts and control plane"
        elif cat == "input_validation":
            actor, vector, asset = "Web attacker", "Unsafe input handling", "Database and application logic"
        else:
            actor, vector, asset = "Opportunistic adversary", "Surface-level abuse", "Service reliability"
        rows.append(
            {
                "actor": actor,
                "vector": vector,
                "asset": asset,
                "mitigation": f["fix"],
            }
        )
    # Dedup to keep report compact
    seen = set()
    compact = []
    for r in rows:
        key = (r["actor"], r["vector"], r["asset"])
        if key in seen:
            continue
        seen.add(key)
        compact.append(r)
    return compact[:10]


def _roadmap(findings: list[dict]) -> list[dict]:
    buckets = {
        "P0": [f for f in findings if f["severity"] == "critical"],
        "P1": [f for f in findings if f["severity"] == "high"],
        "P2": [f for f in findings if f["severity"] == "medium"],
        "P3": [f for f in findings if f["severity"] == "low"],
    }
    effort = {"P0": "1-3 days", "P1": "3-7 days", "P2": "1-2 weeks", "P3": "2-4 weeks"}
    impact = {"P0": "Immediate risk reduction", "P1": "Strong control improvement", "P2": "Attack surface reduction", "P3": "Hygiene hardening"}
    out = []
    for p in ("P0", "P1", "P2", "P3"):
        issues = buckets[p]
        actions = "; ".join(sorted({i["fix"] for i in issues[:3]})) if issues else "No action required in this cycle."
        out.append({"priority": p, "count": len(issues), "effort": effort[p], "impact": impact[p], "actions": actions})
    return out


def _render_controls(controls: list[dict]) -> str:
    icon = {"pass": "✓", "warn": "~", "fail": "✗"}
    css = {"pass": "ctl-pass", "warn": "ctl-warn", "fail": "ctl-fail"}
    blocks = []
    for c in controls:
        blocks.append(
            f"<div class='control-pill {css[c['status']]}'><span class='bin'>{icon[c['status']]}</span><span>{_esc(c['name'])}</span></div>"
        )
    return "".join(blocks)


def _render_finding_card(f: dict) -> str:
    sev = f["severity"]
    return f"""
    <article class="finding-card {sev}">
      <div class="finding-top">
        <span class="sev-badge {sev}">{_esc(sev.upper())}</span>
        <span class="meta">{_esc(f["finding_id"])}</span>
        <span class="meta">CVSS {_esc(f"{f['cvss']:.1f}")}</span>
        <span class="meta">{_esc(f["cwe"])}</span>
        <h3>{_esc(f["title"])}</h3>
      </div>
      <section><h4>Description</h4><p>{_esc(f["description"])}</p></section>
      <section class="impact-grid">
        <div><h5>Confidentiality</h5><p>{_esc(f["impact_confidentiality"])}</p></div>
        <div><h5>Integrity</h5><p>{_esc(f["impact_integrity"])}</p></div>
        <div><h5>Availability</h5><p>{_esc(f["impact_availability"])}</p></div>
      </section>
      <section><h4>Vulnerable Code</h4><pre>{_esc(f["code"])}</pre></section>
      <section><h4>PoC / Evidence</h4><pre>{_esc(f["evidence"])}</pre></section>
      <section><h4>Fix Recommendation</h4><p>{_esc(f["fix"])}</p></section>
    </article>
    """


def generate_security_report_html(findings: list[dict], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = meta.get("target", "AI-SOC Platform")
    scan_type = meta.get("scan_type", "SIEM + IDS + AI Behavioral Analysis")
    methodology = meta.get("methodology", "Wazuh + Suricata + AI anomaly scoring + analyst triage model")
    version = meta.get("version", "AI-SOC-SEC-REPORT v2.0")
    scan_date = meta.get("scan_date", now)

    counts = Counter(f["severity"] for f in findings)
    overall_score = _risk_score(counts)
    controls = _derive_control_status(findings)
    tm_rows = _threat_model_rows(findings)
    roadmap = _roadmap(findings)

    strengths = [
        "Centralized telemetry from Wazuh, Suricata, and AI anomaly pipelines.",
        "Real-time SOC workflow with severity triage and case handling.",
        "Actionable remediation guidance mapped to operational priority lanes.",
    ]

    findings_html = "".join(_render_finding_card(f) for f in findings) or "<p class='muted'>No findings in selected window.</p>"
    tm_html = "".join(
        f"<tr><td>{_esc(r['actor'])}</td><td>{_esc(r['vector'])}</td><td>{_esc(r['asset'])}</td><td>{_esc(r['mitigation'])}</td></tr>"
        for r in tm_rows
    ) or "<tr><td colspan='4'>No mapped threats.</td></tr>"
    roadmap_html = "".join(
        f"<tr><td>{_esc(r['priority'])}</td><td>{_esc(r['count'])}</td><td>{_esc(r['effort'])}</td><td>{_esc(r['impact'])}</td><td>{_esc(r['actions'])}</td></tr>"
        for r in roadmap
    )
    strengths_html = "".join(f"<li>{_esc(s)}</li>" for s in strengths)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
    <title>AI-SOC Security Intelligence Report</title>
  <style>
    :root {{
      --bg:#070b12; --bg-soft:#0d1320; --panel:#111a2b; --text:#d7e2ff; --muted:#8ea3c9; --line:#21304c;
      --critical:#ff3b3b; --high:#ff8b2d; --medium:#f4b641; --low:#22d67a; --info:#37d6ff;
    }}
    *{{box-sizing:border-box}} html,body{{margin:0;background:radial-gradient(1400px 800px at 65% -10%,#1b2b4d 0%,var(--bg) 45%);color:var(--text);font:14px/1.55 "Segoe UI",Arial,sans-serif}}
    .layout{{display:flex;min-height:100vh}}
    .sidebar{{position:fixed;left:0;top:0;bottom:0;width:260px;padding:20px;background:linear-gradient(180deg,#0b1220,#0a101b);border-right:1px solid var(--line)}}
    .sidebar h1{{font-size:15px;margin:0 0 14px;color:var(--info);letter-spacing:.04em;text-transform:uppercase}}
    .sidebar a{{display:block;padding:8px 10px;margin:6px 0;border-radius:8px;color:var(--text);text-decoration:none;background:#0f1727;border:1px solid #16263f}}
    .sidebar a:hover{{border-color:var(--info);color:#fff}}
    .main{{margin-left:260px;flex:1;padding:24px 28px 60px;max-width:1400px}}
    .hero{{background:linear-gradient(135deg,#131f37,#101a2e);border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-bottom:18px}}
    .hero h2{{margin:0 0 8px;font-size:24px}} .hero-grid{{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));gap:10px;margin-top:12px}}
    .kv{{background:#0d1729;border:1px solid var(--line);padding:10px;border-radius:10px}} .k{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}} .v{{font-weight:600}}
    .section{{margin-top:20px}} .section h3{{margin:0 0 10px;font-size:18px;color:#f0f5ff}}
    .score-grid{{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:10px}}
    .score{{padding:14px;border-radius:12px;border:1px solid var(--line);background:var(--panel)}} .score .n{{font-size:28px;font-weight:700}}
    .score.risk .n{{color:var(--critical)}} .score.critical .n{{color:var(--critical)}} .score.high .n{{color:var(--high)}} .score.medium .n{{color:var(--medium)}} .score.low .n{{color:var(--low)}}
    .controls{{display:flex;gap:10px;flex-wrap:wrap}} .control-pill{{display:flex;gap:8px;align-items:center;padding:8px 11px;border-radius:999px;border:1px solid var(--line);background:#111c30}}
    .ctl-pass{{border-color:rgba(34,214,122,.4);color:var(--low)}} .ctl-warn{{border-color:rgba(244,182,65,.4);color:var(--medium)}} .ctl-fail{{border-color:rgba(255,59,59,.45);color:var(--critical)}}
    .bin{{font-weight:700}}
    ul.clean{{margin:0;padding-left:18px}}
    .finding-card{{border:1px solid var(--line);border-left-width:4px;border-radius:12px;background:var(--panel);padding:14px;margin:12px 0}}
    .finding-card.critical{{border-left-color:var(--critical)}} .finding-card.high{{border-left-color:var(--high)}} .finding-card.medium{{border-left-color:var(--medium)}} .finding-card.low{{border-left-color:var(--low)}}
    .finding-top{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} .finding-top h3{{margin:6px 0 0;font-size:17px;flex:1 0 100%}}
    .sev-badge{{padding:3px 8px;border-radius:999px;font-weight:700;font-size:11px;letter-spacing:.04em}}
    .sev-badge.critical{{background:rgba(255,59,59,.18);color:var(--critical)}} .sev-badge.high{{background:rgba(255,139,45,.16);color:var(--high)}} .sev-badge.medium{{background:rgba(244,182,65,.16);color:var(--medium)}} .sev-badge.low{{background:rgba(34,214,122,.16);color:var(--low)}}
    .meta{{background:#0e182b;border:1px solid #213452;border-radius:999px;padding:3px 8px;font-size:11px;color:#b8c8e6}}
    .finding-card h4{{margin:12px 0 5px;color:#dce6ff}} .finding-card p{{margin:0}}
    pre{{margin:0;background:#0b1322;border:1px solid #1f2e4d;padding:10px;border-radius:8px;color:#dbe5ff;white-space:pre-wrap;word-break:break-word}}
    .impact-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}}
    .impact-grid div{{background:#101a2e;border:1px solid var(--line);padding:10px;border-radius:8px}}
    table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
    th,td{{border-bottom:1px solid var(--line);padding:10px;text-align:left;vertical-align:top}} th{{background:#0f182a;color:#dfe8ff;font-size:12px;letter-spacing:.05em;text-transform:uppercase}}
    .muted{{color:var(--muted)}}
    @media (max-width:1024px) {{
      .sidebar{{position:static;width:100%;height:auto}}
      .main{{margin-left:0}}
      .layout{{display:block}}
      .hero-grid,.score-grid,.impact-grid{{grid-template-columns:1fr 1fr}}
    }}
    @media (max-width:640px) {{
      .hero-grid,.score-grid,.impact-grid{{grid-template-columns:1fr}}
    }}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="sidebar">
      <h1>Table of Contents</h1>
      <a href="#executive">1. Executive Summary</a>
      <a href="#scorecard">2. Score Card</a>
      <a href="#strengths">3. Security Strengths</a>
      <a href="#findings">4. Findings</a>
      <a href="#threat-model">5. Threat Model</a>
      <a href="#roadmap">6. Remediation Roadmap</a>
    </aside>
    <main class="main">
      <section class="hero" id="executive">
        <h2>AI-SOC Security Intelligence Report</h2>
        <p class="muted">Decision-support intelligence report for SOC leadership and engineering action.</p>
        <div class="hero-grid">
          <div class="kv"><div class="k">Target</div><div class="v">{_esc(target)}</div></div>
          <div class="kv"><div class="k">Scan Type</div><div class="v">{_esc(scan_type)}</div></div>
          <div class="kv"><div class="k">Scan Date</div><div class="v">{_esc(scan_date)}</div></div>
          <div class="kv"><div class="k">Version</div><div class="v">{_esc(version)}</div></div>
          <div class="kv"><div class="k">Methodology</div><div class="v">{_esc(methodology)}</div></div>
        </div>
      </section>

      <section class="section" id="scorecard">
        <h3>Score Card</h3>
        <div class="score-grid">
          <div class="score risk"><div class="k">Overall Risk Score</div><div class="n">{_esc(overall_score)}</div></div>
          <div class="score critical"><div class="k">Critical</div><div class="n">{_esc(counts['critical'])}</div></div>
          <div class="score high"><div class="k">High</div><div class="n">{_esc(counts['high'])}</div></div>
          <div class="score medium"><div class="k">Medium</div><div class="n">{_esc(counts['medium'])}</div></div>
          <div class="score low"><div class="k">Low</div><div class="n">{_esc(counts['low'])}</div></div>
        </div>
      </section>

      <section class="section">
        <h3>Summary Bar</h3>
        <div class="controls">{_render_controls(controls)}</div>
      </section>

      <section class="section" id="strengths">
        <h3>Security Strengths</h3>
        <ul class="clean">{strengths_html}</ul>
      </section>

      <section class="section" id="findings">
        <h3>Findings (Critical to Low)</h3>
        {findings_html}
      </section>

      <section class="section" id="threat-model">
        <h3>Threat Model</h3>
        <table>
          <thead><tr><th>Actor</th><th>Vector</th><th>Asset</th><th>Mitigation</th></tr></thead>
          <tbody>{tm_html}</tbody>
        </table>
      </section>

      <section class="section" id="roadmap">
        <h3>Remediation Roadmap</h3>
        <table>
          <thead><tr><th>Priority</th><th>Findings</th><th>Effort</th><th>Impact</th><th>Actions</th></tr></thead>
          <tbody>{roadmap_html}</tbody>
        </table>
      </section>
    </main>
  </div>
</body>
</html>
"""
