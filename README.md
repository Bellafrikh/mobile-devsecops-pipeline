# Mobile DevSecOps Pipeline : CI/CD + Triage IA 🚀

## 📝 Présentation du Projet
Ce projet, réalisé à l'**École Marocaine des Sciences de l'Ingénieur (EMSI)** , consiste en l'implémentation d'un pipeline **DevSecOps** complet pour la sécurisation des applications Android. L'objectif est d'automatiser l'intégration de la sécurité à chaque phase du cycle de vie du logiciel (Shift-Left Security), depuis la conception jusqu'au déploiement.

Le pipeline se distingue par l'utilisation d'un **moteur de triage intelligent basé sur l'intelligence artificielle** (Ollama/Llama 3.2) pour analyser et prioriser les vulnérabilités détectées en local.

---

## 🏗️ Architecture du Pipeline
Le flux de travail suit une progression séquentielle automatisée:
1.  **Analyse des Secrets** : Détection de clés API ou tokens exposés avec **Gitleaks**.
2.  **Analyse SAST** : Analyse statique du code source avec **Semgrep**.
3.  **Analyse de Sécurité Mobile** : Scan approfondi de l'application via **MobSF**.
4.  **Triage IA** : Analyse des résultats par **Llama 3.2** en local pour éliminer la "fatigue d'alerte".
5.  **Reporting** : Génération automatique d'un rapport HTML professionnel avec un score de risque global.

---

## 🛠️ Technologies & Outils
| Outil | Rôle dans le pipeline | Version |
| :--- | :--- | :--- |
| **Java (JDK)** | Environnement d'exécution Android | 21.0.9 LTS |
| **Python** | Script de triage IA | 3.13.0  |
| **Gitleaks** | Détection de secrets dans le code | 8.18.0  |
| **Semgrep** | Analyse statique du code (SAST) | 1.161.0  |
| **MobSF** | Analyse sécurité des applications mobiles | 4.5.0  |
| **Docker** | Conteneurisation de MobSF | Desktop  |
| **Ollama (Llama 3.2)** | Modèle IA local pour le triage | 2.0 GB  |
| **GitHub Actions** | Pipeline CI/CD automatisé | ---  |

---

## 🛡️ Vulnérabilités Cibles (MainActivity.java)
Une application Android a été conçue délibérément avec plusieurs failles pour valider le pipeline:
* **CWE-89** : Injection SQL par concaténation de chaînes.
* **CWE-798** : Identifiants (clés API) codés en dur dans le code source .
* **CWE-532** : Données sensibles exposées via `Log.d()`.
* **CWE-489** : Application déboguable en production (`debuggable="true"`).
* **CWE-79** : JavaScript activé sans restriction dans WebView.

---

## 🚀 Installation & Utilisation Locale

### Prérequis
* Docker Desktop installé pour MobSF.
* Ollama installé avec le modèle Llama 3.2 (`ollama pull llama3.2`).
* Python 3.13 installé.

### Exécution du Triage IA
Pour lancer l'analyse intelligente sur vos rapports locaux :
```bash
# Installer les dépendances Python
pip install requests json datetime
```
##📊 Résultats du Pipeline CI/CD 

[cite_start]Le pipeline **GitHub Actions** orchestre trois jobs principaux exécutés de manière séquentielle:

* **Secrets Detection** : L'outil **Gitleaks** a détecté avec succès **2 secrets** (`API_KEY` et `SECRET_TOKEN`) exposés dans le code source.
* **SAST Analysis** : Une analyse statique approfondie a été effectuée par **Semgrep** pour identifier les patterns de code vulnérables.
* **AI Triage** : Un triage automatisé assisté par l'IA (**Llama 3.2**) a été réalisé, aboutissant à la génération du rapport de sécurité final.
* **Score de Risque Global** : L'analyse a attribué un score de **55/100** au projet.

---

## 👥 Contributeurs 

* **BELLAFRIKH Zaynab** — Étudiante en 4ème année à l'**EMSI**.
* **BAZAR Ilham** — Collaboratrice sur le projet.
* **Pr.LACHGAR Mohammed** — Projet réalisé sous sa direction.

---

**Date de réalisation** : 26 Avril 2026.
**Institution** : École Marocaine des Sciences de l'Ingénieur (**EMSI**).

# Lancer le script de triage (assurez-vous que Ollama est actif)
python scripts/ai_triage.py
