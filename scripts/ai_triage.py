#!/usr/bin/env python3
"""
AI Triage Engine - Analyse et priorise les vulnérabilités
avec l'API Claude/Anthropic
"""

import json
import os
from datetime import datetime

# ─── Chargement des rapports ───────────────────────────────────────────────

def load_semgrep_results():
    """Charger les résultats Semgrep"""
    results = []
    try:
        filepath = os.path.join("security-reports", "semgrep-results.json")
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
            for finding in data.get("results", []):
                results.append({
                    "tool": "Semgrep",
                    "type": "SAST",
                    "rule": finding.get("check_id", "unknown"),
                    "severity": finding.get("extra", {}).get("severity", "MEDIUM"),
                    "message": finding.get("extra", {}).get("message", ""),
                    "file": finding.get("path", ""),
                    "line": finding.get("start", {}).get("line", 0),
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", [])
                })
        print(f"[OK] Semgrep : {len(results)} findings chargés")
    except Exception as e:
        print(f"[WARN] Semgrep results pas trouvés : {e}")
    return results


def load_mobsf_results():
    """Charger les résultats MobSF"""
    results = []
    try:
        filepath = os.path.join("security-reports", "mobsf-results.json")
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
            for severity in ["high", "warning", "info"]:
                findings = data.get(severity, {})
                for key, finding in findings.items():
                    results.append({
                        "tool": "MobSF",
                        "type": "Mobile SAST",
                        "rule": key,
                        "severity": severity.upper(),
                        "message": finding.get("description", ""),
                        "file": (finding.get("files", ["unknown"])[0]
                                 if finding.get("files") else "unknown"),
                        "line": 0,
                        "cwe": finding.get("cwe", "")
                    })
        print(f"[OK] MobSF : {len(results)} findings chargés")
    except Exception as e:
        print(f"[WARN] MobSF results pas trouvés : {e}")
    return results


# ─── Triage IA ─────────────────────────────────────────────────────────────

def ai_triage_vulnerabilities(vulnerabilities):
    """Utiliser Claude pour trier et analyser les vulnérabilités"""

    import anthropic
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    vuln_summary = json.dumps(vulnerabilities[:20], indent=2)

    prompt = f"""
Tu es un expert en sécurité mobile (Android/iOS). Analyse ces vulnérabilités
détectées par des outils SAST et priorise-les.

VULNÉRABILITÉS DÉTECTÉES :
{vuln_summary}

Pour chaque vulnérabilité, fournis :
- tool: nom de l'outil
- rule: nom de la règle
- file: fichier concerné
- priority: CRITICAL/HIGH/MEDIUM/LOW/INFO
- exploitability: score 1-10
- business_impact: description courte de l'impact
- false_positive_probability: LOW/MEDIUM/HIGH
- remediation: correction concrète en 1-2 phrases
- owasp_mobile_top10: catégorie OWASP Mobile Top 10

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après :
{{
  "summary": {{
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "risk_score": 0
  }},
  "triaged_vulnerabilities": []
}}
"""

    print("[IA] Envoi à Claude API...")
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )

    response_text = message.content[0].text
    # Nettoyer si besoin
    response_text = response_text.strip()
    if response_text.startswith("```"):
        response_text = response_text.split("```")[1]
        if response_text.startswith("json"):
            response_text = response_text[4:]
    return json.loads(response_text)


# ─── Génération du rapport HTML ─────────────────────────────────────────────

def generate_html_report(triage_results, vulnerabilities):
    """Générer un rapport HTML professionnel"""

    summary = triage_results.get("summary", {})
    triaged = triage_results.get("triaged_vulnerabilities", [])

    rows = ""
    for vuln in triaged[:50]:
        sev = vuln.get('priority', 'INFO').lower()
        rows += f"""
        <tr>
            <td>{vuln.get('tool', 'N/A')}</td>
            <td><span class="badge badge-{sev}">{vuln.get('priority', 'INFO')}</span></td>
            <td style="font-size:0.85em">{vuln.get('rule', 'N/A')}</td>
            <td style="font-family:monospace;font-size:0.8em">{vuln.get('file', 'N/A')}</td>
            <td>{vuln.get('business_impact', 'N/A')}</td>
            <td>{vuln.get('remediation', 'N/A')}</td>
            <td>{vuln.get('owasp_mobile_top10', 'N/A')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Mobile Security Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }}
        .header {{ background: linear-gradient(135deg, #1e40af, #7c3aed); padding: 40px; text-align: center; }}
        h1 {{ font-size: 2em; }}
        .subtitle {{ opacity: 0.8; margin-top: 8px; }}
        .container {{ max-width: 1300px; margin: 0 auto; padding: 30px; }}
        .grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin: 30px 0; }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 20px; text-align: center; border: 1px solid #334155; }}
        .number {{ font-size: 2.5em; font-weight: bold; }}
        .critical {{ color: #ef4444; }}
        .high {{ color: #f97316; }}
        .medium {{ color: #eab308; }}
        .low {{ color: #22c55e; }}
        .info {{ color: #60a5fa; }}
        .risk-bar {{ background: #1e293b; border-radius: 12px; padding: 20px; margin: 20px 0; }}
        .bar-bg {{ background: #334155; border-radius: 10px; height: 20px; }}
        .bar {{ height: 20px; border-radius: 10px; background: linear-gradient(90deg, #22c55e, #eab308, #ef4444); transition: width 1s; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }}
        th {{ background: #1e293b; padding: 12px; text-align: left; border-bottom: 2px solid #334155; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
        tr:hover {{ background: #1e293b55; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #14532d; color: #86efac; }}
        .badge-info {{ background: #1e3a5f; color: #93c5fd; }}
        .timestamp {{ text-align: right; opacity: 0.4; font-size: 0.8em; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1> Mobile DevSecOps Security Report</h1>
        <div class="subtitle">Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • Powered by Claude AI</div>
    </div>
    <div class="container">
        <div class="grid">
            <div class="card"><div class="number critical">{summary.get('critical', 0)}</div><div>Critical</div></div>
            <div class="card"><div class="number high">{summary.get('high', 0)}</div><div>High</div></div>
            <div class="card"><div class="number medium">{summary.get('medium', 0)}</div><div>Medium</div></div>
            <div class="card"><div class="number low">{summary.get('low', 0)}</div><div>Low</div></div>
            <div class="card"><div class="number info">{summary.get('risk_score', 0)}<span style="font-size:0.5em">/100</span></div><div>Risk Score</div></div>
        </div>

        <div class="risk-bar">
            <h3 style="margin-bottom:12px"> Niveau de risque global</h3>
            <div class="bar-bg">
                <div class="bar" style="width:{summary.get('risk_score', 0)}%"></div>
            </div>
            <div style="text-align:right; margin-top:6px; opacity:0.6">{summary.get('risk_score', 0)}%</div>
        </div>

        <h2 style="margin-top:30px"> Vulnérabilités triées par IA</h2>
        <table>
            <thead>
                <tr>
                    <th>Outil</th>
                    <th>Sévérité</th>
                    <th>Règle</th>
                    <th>Fichier</th>
                    <th>Impact</th>
                    <th>Remédiation</th>
                    <th>OWASP Mobile</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        <div class="timestamp">Mobile DevSecOps Pipeline — {datetime.now().strftime('%Y')}</div>
    </div>
</body>
</html>"""
    return html


# ─── MAIN ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 50)
    print("  MOBILE DEVSECOPS — AI TRIAGE ENGINE")
    print("=" * 50)

    print("\n Chargement des rapports...")
    vulnerabilities = []
    vulnerabilities.extend(load_semgrep_results())
    vulnerabilities.extend(load_mobsf_results())

    print(f"\n Total : {len(vulnerabilities)} vulnérabilités trouvées")

    # Mode démo si aucun résultat réel
    if not vulnerabilities:
        print("[INFO] Aucun rapport trouvé → mode démo activé")
        vulnerabilities = [
            {
                "tool": "Semgrep", "type": "SAST",
                "rule": "hardcoded-credentials", "severity": "HIGH",
                "message": "Hardcoded API key found in source code",
                "file": "MainActivity.java", "line": 12,
                "cwe": ["CWE-798"]
            },
            {
                "tool": "Semgrep", "type": "SAST",
                "rule": "sql-injection", "severity": "CRITICAL",
                "message": "SQL Injection via string concatenation",
                "file": "MainActivity.java", "line": 28,
                "cwe": ["CWE-89"]
            },
            {
                "tool": "MobSF", "type": "Mobile SAST",
                "rule": "android_allowbackup", "severity": "WARNING",
                "message": "Android allowBackup is enabled",
                "file": "AndroidManifest.xml", "line": 0,
                "cwe": "CWE-530"
            },
            {
                "tool": "MobSF", "type": "Mobile SAST",
                "rule": "android_debuggable", "severity": "HIGH",
                "message": "Application is debuggable",
                "file": "AndroidManifest.xml", "line": 0,
                "cwe": "CWE-489"
            },
            {
                "tool": "Semgrep", "type": "SAST",
                "rule": "sensitive-log", "severity": "MEDIUM",
                "message": "Sensitive data logged in plaintext",
                "file": "MainActivity.java", "line": 22,
                "cwe": ["CWE-532"]
            }
        ]

    print("\n Analyse IA en cours (Claude API)...")
    triage_results = ai_triage_vulnerabilities(vulnerabilities)

    # Créer le dossier si nécessaire
    os.makedirs("security-reports", exist_ok=True)

    # Sauvegarder le résumé JSON
    summary = triage_results.get("summary", {})
    with open(os.path.join("security-reports", "triage-summary.json"), "w") as f:
        json.dump({
            "critical_count": summary.get("critical", 0),
            "total": summary.get("total", 0),
            "risk_score": summary.get("risk_score", 0)
        }, f, indent=2)

    # Générer le rapport HTML
    html = generate_html_report(triage_results, vulnerabilities)
    report_path = os.path.join("security-reports", "final-report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n Rapport généré : {report_path}")
    print(f"""
╔══════════════════════════════════╗
║     SECURITY TRIAGE SUMMARY      ║
╠══════════════════════════════════╣
║  Critical  : {summary.get('critical', 0):<23}║
║  High      : {summary.get('high', 0):<23}║
║  Medium    : {summary.get('medium', 0):<23}║
║  Low       : {summary.get('low', 0):<23}║
║  Risk Score: {summary.get('risk_score', 0)}/100{' ' * 18}║
╚══════════════════════════════════╝
    """)

    # Ouvrir automatiquement le rapport
    import subprocess
    subprocess.Popen(["start", report_path], shell=True)


if __name__ == "__main__":
    main()