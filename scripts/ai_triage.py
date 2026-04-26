#!/usr/bin/env python3
import json
import os
import urllib.request
from datetime import datetime

# ── 1. Charger Semgrep ─────────────────────────────────────────────────────

def load_semgrep_results():
    results = []
    try:
        path = os.path.join("security-reports", "semgrep-results.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for finding in data.get("results", []):
            results.append({
                "tool":     "Semgrep",
                "type":     "SAST",
                "rule":     finding.get("check_id", "unknown"),
                "severity": finding.get("extra", {}).get("severity", "MEDIUM"),
                "message":  finding.get("extra", {}).get("message", ""),
                "file":     finding.get("path", ""),
                "line":     finding.get("start", {}).get("line", 0),
                "cwe":      finding.get("extra", {}).get("metadata", {}).get("cwe", [])
            })
        print(f"[OK] Semgrep : {len(results)} finding(s)")
    except Exception as e:
        print(f"[WARN] Semgrep : {e}")
    return results

# ── 2. Charger MobSF ───────────────────────────────────────────────────────

def load_mobsf_results():
    results = []
    try:
        path = os.path.join("security-reports", "mobsf-results.json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for severity in ["high", "warning", "info"]:
            findings = data.get(severity, {})
            for key, finding in findings.items():
                results.append({
                    "tool":     "MobSF",
                    "type":     "Mobile SAST",
                    "rule":     key,
                    "severity": severity.upper(),
                    "message":  finding.get("description", ""),
                    "file":     (finding.get("files", ["unknown"])[0]
                                 if finding.get("files") else "unknown"),
                    "line":     0,
                    "cwe":      finding.get("cwe", "")
                })
        print(f"[OK] MobSF : {len(results)} finding(s)")
    except Exception as e:
        print(f"[WARN] MobSF : {e}")
    return results

# ── 3. Triage via Ollama ───────────────────────────────────────────────────

def ai_triage(vulnerabilities):
    vuln_json = json.dumps(vulnerabilities[:20], indent=2)

    prompt = f"""Tu es un expert en sécurité mobile Android/iOS.
Voici les vulnérabilités détectées :

{vuln_json}

Réponds UNIQUEMENT avec du JSON valide, sans texte avant ni après :
{{
  "summary": {{
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "risk_score": 0
  }},
  "triaged_vulnerabilities": [
    {{
      "tool": "",
      "rule": "",
      "file": "",
      "priority": "CRITICAL ou HIGH ou MEDIUM ou LOW ou INFO",
      "exploitability": 0,
      "business_impact": "",
      "false_positive_probability": "LOW ou MEDIUM ou HIGH",
      "remediation": "",
      "owasp_mobile_top10": ""
    }}
  ]
}}"""

    payload = json.dumps({
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False
    }).encode("utf-8")

    print("[IA] Envoi à Ollama (local)...")
    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[ERREUR] Ollama ne répond pas : {e}")
        print("[INFO] Génération d'un rapport de secours...")
        return generate_fallback(vulnerabilities)

    text = result.get("response", "").strip()

    # Nettoyer les backticks si présents
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:].strip()
            if part.startswith("{"):
                text = part
                break

    # Trouver le JSON dans la réponse
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start != -1 and end > start:
        text = text[start:end]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        print("[WARN] JSON invalide reçu d'Ollama → rapport de secours")
        return generate_fallback(vulnerabilities)

# ── 4. Rapport de secours si Ollama échoue ────────────────────────────────

def generate_fallback(vulnerabilities):
    triaged = []
    critical = high = medium = low = 0
    for v in vulnerabilities:
        sev = v.get("severity", "MEDIUM").upper()
        if sev in ["CRITICAL"]:
            priority = "CRITICAL"; critical += 1
        elif sev in ["HIGH"]:
            priority = "HIGH"; high += 1
        elif sev in ["WARNING", "MEDIUM"]:
            priority = "MEDIUM"; medium += 1
        else:
            priority = "LOW"; low += 1
        triaged.append({
            "tool":                      v.get("tool", ""),
            "rule":                      v.get("rule", ""),
            "file":                      v.get("file", ""),
            "priority":                  priority,
            "exploitability":            5,
            "business_impact":           "Risque de sécurité détecté",
            "false_positive_probability":"MEDIUM",
            "remediation":               "Analyser et corriger selon les bonnes pratiques OWASP",
            "owasp_mobile_top10":        "M1 - Improper Platform Usage"
        })
    total = critical + high + medium + low
    risk  = min(100, critical * 25 + high * 10 + medium * 5 + low * 2)
    return {
        "summary": {
            "total": total, "critical": critical, "high": high,
            "medium": medium, "low": low, "risk_score": risk
        },
        "triaged_vulnerabilities": triaged
    }

# ── 5. Générer le rapport HTML ─────────────────────────────────────────────

def generate_report(triage, vulns):
    summary = triage.get("summary", {})
    triaged = triage.get("triaged_vulnerabilities", [])

    rows = ""
    for v in triaged[:50]:
        sev = v.get("priority", "INFO").lower()
        rows += f"""
        <tr>
          <td>{v.get('tool','')}</td>
          <td><span class="badge {sev}">{v.get('priority','INFO')}</span></td>
          <td style="font-size:.85em">{v.get('rule','')}</td>
          <td style="font-family:monospace;font-size:.8em">{v.get('file','')}</td>
          <td>{v.get('business_impact','')}</td>
          <td>{v.get('remediation','')}</td>
          <td style="font-size:.85em">{v.get('owasp_mobile_top10','')}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Mobile Security Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0}}
  .header{{background:linear-gradient(135deg,#1e40af,#7c3aed);padding:40px;text-align:center}}
  h1{{font-size:2em}} .sub{{opacity:.8;margin-top:8px}}
  .wrap{{max-width:1300px;margin:0 auto;padding:30px}}
  .grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin:30px 0}}
  .card{{background:#1e293b;border-radius:12px;padding:20px;text-align:center;border:1px solid #334155}}
  .num{{font-size:2.4em;font-weight:bold}}
  .crit{{color:#ef4444}} .hi{{color:#f97316}} .med{{color:#eab308}}
  .lo{{color:#22c55e}} .inf{{color:#60a5fa}}
  .riskbar{{background:#1e293b;border-radius:12px;padding:20px;margin:20px 0}}
  .rbg{{background:#334155;border-radius:10px;height:18px}}
  .rb{{height:18px;border-radius:10px;background:linear-gradient(90deg,#22c55e,#eab308,#ef4444)}}
  table{{width:100%;border-collapse:collapse;margin-top:20px;font-size:.9em}}
  th{{background:#1e293b;padding:12px;text-align:left;border-bottom:2px solid #334155}}
  td{{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}}
  tr:hover{{background:#1e293b88}}
  .badge{{padding:3px 10px;border-radius:20px;font-size:.8em;font-weight:bold}}
  .critical{{background:#7f1d1d;color:#fca5a5}}
  .high{{background:#7c2d12;color:#fdba74}}
  .medium{{background:#713f12;color:#fde047}}
  .low{{background:#14532d;color:#86efac}}
  .info{{background:#1e3a5f;color:#93c5fd}}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Mobile DevSecOps — Security Report</h1>
  <div class="sub">Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • Powered by Ollama (llama3.2)</div>
</div>
<div class="wrap">
  <div class="grid">
    <div class="card"><div class="num crit">{summary.get('critical',0)}</div><div>Critical</div></div>
    <div class="card"><div class="num hi">{summary.get('high',0)}</div><div>High</div></div>
    <div class="card"><div class="num med">{summary.get('medium',0)}</div><div>Medium</div></div>
    <div class="card"><div class="num lo">{summary.get('low',0)}</div><div>Low</div></div>
    <div class="card"><div class="num inf">{summary.get('risk_score',0)}<span style="font-size:.5em">/100</span></div><div>Risk Score</div></div>
  </div>
  <div class="riskbar">
    <h3 style="margin-bottom:12px">📊 Niveau de risque global</h3>
    <div class="rbg"><div class="rb" style="width:{summary.get('risk_score',0)}%"></div></div>
    <div style="text-align:right;margin-top:6px;opacity:.6">{summary.get('risk_score',0)}%</div>
  </div>
  <h2 style="margin-top:30px">🤖 Vulnérabilités triées par IA (Ollama)</h2>
  <table>
    <thead>
      <tr>
        <th>Outil</th><th>Sévérité</th><th>Règle</th>
        <th>Fichier</th><th>Impact</th><th>Remédiation</th><th>OWASP Mobile</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>
</body>
</html>"""

# ── 6. MAIN ────────────────────────────────────────────────────────────────

def main():
    print("=" * 50)
    print("   MOBILE DEVSECOPS — AI TRIAGE ENGINE (Ollama)")
    print("=" * 50)

    print("\n Chargement des rapports...")
    vulns = []
    vulns.extend(load_semgrep_results())
    vulns.extend(load_mobsf_results())
    print(f"\n📊 Total : {len(vulns)} vulnérabilité(s)")

    if not vulns:
        print("[INFO] Aucun rapport → mode démo")
        vulns = [
            {"tool":"Semgrep","type":"SAST","rule":"hardcoded-credentials",
             "severity":"HIGH","message":"Hardcoded API key in source code",
             "file":"MainActivity.java","line":12,"cwe":["CWE-798"]},
            {"tool":"Semgrep","type":"SAST","rule":"sql-injection",
             "severity":"CRITICAL","message":"SQL Injection via string concat",
             "file":"MainActivity.java","line":28,"cwe":["CWE-89"]},
            {"tool":"Semgrep","type":"SAST","rule":"sensitive-log",
             "severity":"MEDIUM","message":"Sensitive data in logs",
             "file":"MainActivity.java","line":22,"cwe":["CWE-532"]},
            {"tool":"MobSF","type":"Mobile SAST","rule":"android_allowbackup",
             "severity":"WARNING","message":"allowBackup enabled",
             "file":"AndroidManifest.xml","line":0,"cwe":"CWE-530"},
            {"tool":"MobSF","type":"Mobile SAST","rule":"android_debuggable",
             "severity":"HIGH","message":"App is debuggable",
             "file":"AndroidManifest.xml","line":0,"cwe":"CWE-489"},
        ]

    print("\n🤖 Analyse IA via Ollama (llama3.2)...")
    print("    (patiente 1-2 minutes, c'est normal...)\n")

    triage = ai_triage(vulns)

    os.makedirs("security-reports", exist_ok=True)

    summary = triage.get("summary", {})
    with open(os.path.join("security-reports","triage-summary.json"), "w") as f:
        json.dump({
            "critical_count": summary.get("critical", 0),
            "total":          summary.get("total", 0),
            "risk_score":     summary.get("risk_score", 0)
        }, f, indent=2)

    html = generate_report(triage, vulns)
    report_path = os.path.join("security-reports", "final-report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"✅ Rapport généré : {report_path}")
    print(f"""
╔══════════════════════════════════╗
║       SECURITY TRIAGE SUMMARY    ║
╠══════════════════════════════════╣
║  Critical  : {summary.get('critical',0):<23}║
║  High      : {summary.get('high',0):<23}║
║  Medium    : {summary.get('medium',0):<23}║
║  Low       : {summary.get('low',0):<23}║
║  Risk Score: {summary.get('risk_score',0)}/100{' '*18}║
╚══════════════════════════════════╝
    """)

    import subprocess
    subprocess.Popen(["start", report_path], shell=True)

if __name__ == "__main__":
    main()