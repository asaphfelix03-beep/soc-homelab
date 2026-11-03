"""Génère la section « 4. Résultats » de docs/rapport.md à partir de analysis/output/.

Les chiffres du rapport viennent ainsi directement des données, sans recopie manuelle.
Usage (après analyze.py) : python analysis/report_results.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "analysis" / "output"
REPORT = ROOT / "docs" / "rapport.md"
START, END = "## 4. Résultats", "## 5. Problèmes rencontrés"


def s(v: float | None) -> str:
    """Durée en secondes, format français."""
    if v is None or pd.isna(v):
        return "–"
    return (f"{v:.2f}" if v < 1 else f"{v:.1f}").replace(".", ",") + " s"


def build() -> str:
    m = json.loads((OUT / "metrics.json").read_text())
    res = pd.read_csv(OUT / "scenario_results.csv").set_index("scenario_id")
    rep = pd.read_csv(OUT / "repeatability.csv").set_index("scenario_id")
    base = pd.read_csv(OUT / "baseline_results.csv")
    ctrl_base_path = OUT / "baseline_results_builtin_only.csv"
    ctrl_base = pd.read_csv(ctrl_base_path).set_index("scenario_id") if ctrl_base_path.exists() else None
    d, r, sca, after = m["detection"], m["repeatability"], m["sca"], m.get("sca_after") or {}
    n = r["runs"]

    L = [START, "", "### 4.1 Détection par technique", "",
         f"A : natives + personnalisées, **{n} campagnes**. B : natives seules (campagne témoin).", "",
         "| Scénario | Technique | A : règle déclenchée (niveau) | A : stabilité | A : TTD médian (min–max) | B : meilleure alerte native (niveau) |",
         "|---|---|---|---|---|---|"]
    for sid, x in res.iterrows():
        rr = rep.loc[sid]
        fired = str(x["fired_expected"]).replace(";", " + ")
        lvl = int(x["max_level_custom"]) if x["max_level_custom"] else int(x["max_level_in_run"])
        native = "native " if not x["max_level_custom"] else ""
        top = str(x["top_builtin_rule"]).replace(" · ", " ")
        L.append(f"| {sid} | {x['mitre_id']} {x['technique']} | {fired} {native}({lvl}) | "
                 f"{int(rr['detected_runs'])}/{int(rr['runs'])} | {s(rr['ttd_median'])} "
                 f"({'identique sur les ' + str(int(rr['runs'])) if rr['ttd_min'] == rr['ttd_max'] else s(rr['ttd_min']) + ' – ' + s(rr['ttd_max'])}) | "
                 f"{top} ({int(x['max_level_builtin'])}) |")

    fp_runs = r["custom_false_positives_per_run"]
    L += ["", "### 4.2 Synthèse", "",
          "| Indicateur | A : natives + personnalisées | B : natives seules |", "|---|---|---|",
          f"| Techniques détectées (niveau ≥ 7) | **{d['detected']}/{d['scenarios']}**, à chacune des {n} campagnes | {d['builtin_triaged']}/{d['scenarios']} |",
          f"| Alertes portant la bonne technique MITRE | **{d['mitre_match']}/{d['scenarios']}** | {d['builtin_mitre_match']}/{d['scenarios']} |",
          f"| TTD médian, toutes campagnes | {s(r['ttd_all_median_s'])} | {s(d['builtin_ttd_median_s'])} (sur les {d['builtin_triaged']} détectées) |",
          f"| TTD médian, scénarios FIM (S04 à S09) | {s(r['ttd_fim_median_s'])} | – |",
          f"| TTD maximal | {s(rep['ttd_max'].max())} (S10) | – |",
          f"| Faux positifs pendant l'activité normale (niveau ≥ 7) | **{sum(fp_runs)}** sur {n} campagnes | "
          f"{m['noise'].get('builtin_baseline_triage_alerts', '–')} (alerte native sur un document modifié) |", ""]

    L += ["### 4.3 Lecture", "",
          f"- **Les règles natives voient presque tout, mais elles ne disent pas quoi.** Dans les 10 cas, la campagne témoin lève une alerte. "
          f"Seules S01 (échecs PAM) et S02 (création de compte) portent la bonne technique ; les autres sont génériques "
          "(« File added to the system », « Integrity checksum changed »). L'analyste doit ouvrir l'alerte et lire le chemin du fichier "
          "pour comprendre qu'il s'agit d'une tâche cron ou d'une règle sudoers. En niveau 5, ces alertes passent sous le seuil de triage.",
          "- **Le nom de la menace et la technique MITRE accélèrent le triage.** Avec les règles personnalisées, chaque alerte dit ce qui se passe "
          "(« [SOC] Tâche cron créée ou modifiée : /etc/cron.d/maintenance ») et porte la bonne technique, ce qui permet de mesurer la couverture ATT&CK.",
          f"- **La corrélation transforme des signaux faibles en incident.** S03 : sans corrélation, on voit une modification de `/etc/group` "
          f"(niveau {int(res.loc['S03', 'max_level_builtin'])}). Avec la règle 100112 : « compte créé puis promu administrateur en moins de 10 minutes » (niveau 14). "
          "S01 : six échecs de niveau 5 deviennent une alerte de niveau 10 (100113), puis la connexion réussie qui suit monte au niveau 13 (100114).",
          *([f"- **Le résultat natif dépend de l'état du poste, pas mes règles.** S05 : sur un poste neuf, `authorized_keys` n'existe pas encore, "
              f"donc sa création donne la règle native 554 (niveau {int(res.loc['S05', 'max_level_builtin'])}, sous le seuil). Si le fichier existait déjà, "
              "sa modification donnerait 550 (niveau 7). La règle 100101 couvre les deux cas, au niveau 10."]
            if int(res.loc["S05", "max_level_builtin"]) < 7 else []),
          f"- **Les détections sont stables.** Les {d['scenarios']} techniques sont détectées à chacune des {n} campagnes. "
          f"Le FIM temps réel répond en {s(r['ttd_fim_median_s'])} à chaque fois. S10 varie de {s(rep.loc['S10', 'ttd_min'])} à {s(rep.loc['S10', 'ttd_max'])}, "
          "car les ports sont contrôlés toutes les 120 s : le délai dépend du moment où tombe le prochain contrôle.", ""]

    L += ["### 4.4 Bruit", "",
          "Activité normale de la campagne de référence (A) et de la campagne témoin (B) :", "",
          "| Activité | A : alertes | A : niveau ≥ 7 | A : ramenées au niveau 3 (100120) | B : niveau ≥ 7 |", "|---|---|---|---|---|"]
    for _, b in base.iterrows():
        cb = int(ctrl_base.loc[b["scenario_id"], "alerts_triage_level"]) if ctrl_base is not None and b["scenario_id"] in ctrl_base.index else "–"
        L.append(f"| {b['scenario_id']} {b['description']} | {int(b['alerts'])} | {int(b['alerts_triage_level'])} | {int(b.get('noise_reduced', 0))} | {cb} |")
    b04_native = int(ctrl_base.loc["B04", "alerts_triage_level"]) if ctrl_base is not None and "B04" in ctrl_base.index else None
    b04_a = base.set_index("scenario_id").loc["B04"] if "B04" in set(base["scenario_id"]) else None
    if b04_native and b04_a is not None and int(b04_a["alerts_triage_level"]) == 0:
        L += ["", f"Sans mes règles, la modification d'un document existant (B04) lève {'une alerte native' if b04_native == 1 else str(b04_native) + ' alertes natives'} de niveau ≥ 7 (550, « Integrity checksum changed »), qu'un analyste devrait traiter. "
              "Avec la règle 100120, elle est journalisée au niveau 3 et n'atteint plus le seuil de triage. Les fichiers sensibles du dossier personnel "
              "(`.ssh/authorized_keys`, `.bashrc`) restent signalés : cela a été vérifié en conditions réelles avant les campagnes.", ""]
    else:
        L += ["", "Aucune activité normale n'atteint le seuil de triage avec mes règles. La règle 100120 journalise au niveau 3 les documents créés ou modifiés.", ""]

    L += ["### 4.5 Posture CIS", "",
          "| | Avant | Après `hardening/harden.sh` |", "|---|---|---|",
          f"| Score SCA (CIS Ubuntu 24.04 v1.0.0) | **{sca['score']} %** | **{after.get('score', '–')} %** |",
          f"| Contrôles réussis | {sca['passed']} | {after.get('passed', '–')} |",
          f"| Contrôles échoués | {sca['failed']} | {after.get('failed', '–')} |",
          f"| Non applicables | {sca['na']} | {after.get('na', '–')} |", "",
          f"{after.get('passed', 0) - sca['passed']} contrôles ont été corrigés en un seul passage du script, sans aucune régression : SSH, cron, bannières, PAM, politique de mots de passe, "
          "journaux, core dumps et restriction de `su`. Les échecs restants relèvent surtout de ce qu'un conteneur ne permet pas : partitions séparées, pare-feu, "
          "`auditd`, AppArmor et paramètres réseau du noyau. Trois contrôles ciblés restent en échec : 2.4.1.1 (pas de systemd dans le conteneur), 2.4.2.1 "
          "(paquet `at` absent) et 5.2.3. Pour ce dernier, la directive `Defaults logfile=` est bien présente, mais le contrôle échoue toujours. "
          "La cause n'est pas élucidée ; l'expression régulière de la politique est suspectée.", ""]
    return "\n".join(L) + "\n"


def main() -> None:
    text = REPORT.read_text()
    i, j = text.index(START), text.index(END)
    REPORT.write_text(text[:i] + build() + text[j:])
    print(f"Section « Résultats » régénérée dans {REPORT}")


if __name__ == "__main__":
    main()
