"""Analyse des alertes du SOC Homelab.

Rapproche chaque alerte Wazuh du scénario qui l'a provoquée (vérité terrain),
puis calcule les indicateurs d'un SOC :
  - taux de détection par technique MITRE ATT&CK
  - temps de détection (TTD = première alerte attendue - début du scénario)
  - bruit : alertes pendant l'activité normale et faux positifs des règles maison
  - apport des règles personnalisées par rapport aux règles natives de Wazuh
  - posture de sécurité (benchmark CIS via le module SCA)

Usage (depuis la racine du projet) :
    python analysis/analyze.py
Sorties : analysis/output/*.csv, analysis/output/metrics.json, docs/dashboard/data.js
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "analysis" / "data"
OUT = ROOT / "analysis" / "output"
DASH = ROOT / "docs" / "dashboard"

CUSTOM_MIN, CUSTOM_MAX = 100100, 100199   # plage des règles maison
TRIAGE_LEVEL = 7                          # seuil de niveau à partir duquel un analyste traite l'alerte


# ---------------------------------------------------------------- chargement
def load_alerts(path: Path = DATA / "alerts.json") -> pd.DataFrame:
    raw = json.loads(path.read_text())
    rows = []
    for a in raw:
        r = a.get("rule", {})
        rows.append({
            "timestamp": a.get("timestamp"),
            "rule_id": int(r.get("id", 0)),
            "level": int(r.get("level", 0)),
            "description": r.get("description", ""),
            "groups": ",".join(r.get("groups", [])),
            "mitre_ids": ",".join(r.get("mitre", {}).get("id", [])),
            "mitre_tactics": ",".join(r.get("mitre", {}).get("tactic", [])),
            "file": a.get("syscheck", {}).get("path", ""),
            "location": a.get("location", ""),
            "full_log": (a.get("full_log") or "")[:300],
        })
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")
    df["custom"] = df["rule_id"].between(CUSTOM_MIN, CUSTOM_MAX)
    df["posture"] = df["groups"].str.contains(r"(?:^|,)sca(?:,|$)") | df["rule_id"].between(19000, 19999)
    return df.sort_values("timestamp").reset_index(drop=True)


def load_scenarios(gt_path: Path = ROOT / "tests" / "results" / "ground_truth.csv") -> pd.DataFrame:
    sc = pd.read_csv(ROOT / "tests" / "scenarios.csv", dtype=str).fillna("")
    gt = pd.read_csv(gt_path)
    gt["start_utc"] = pd.to_datetime(gt["start_utc"], utc=True, format="ISO8601")
    gt["end_utc"] = pd.to_datetime(gt["end_utc"], utc=True, format="ISO8601")
    gt = gt.sort_values("start_utc").reset_index(drop=True)
    # Fenêtre d'attribution : du début du scénario jusqu'au début du suivant.
    gt["window_end"] = gt["start_utc"].shift(-1)
    gt.loc[gt.index[-1], "window_end"] = gt["end_utc"].iloc[-1] + pd.Timedelta(seconds=60)
    df = gt.merge(sc, on="scenario_id", how="left")
    df.loc[df["scenario_id"].str.startswith("C"), "type"] = "cleanup"
    return df


def attribute(alerts: pd.DataFrame, scen: pd.DataFrame) -> pd.DataFrame:
    alerts = alerts.copy()
    alerts["scenario_id"] = ""
    for _, s in scen.iterrows():
        m = (alerts["timestamp"] >= s["start_utc"]) & (alerts["timestamp"] < s["window_end"])
        alerts.loc[m, "scenario_id"] = s["scenario_id"]
    types = dict(zip(scen["scenario_id"], scen["type"]))
    alerts["phase"] = alerts["scenario_id"].map(types).fillna("hors_test")
    alerts.loc[alerts["scenario_id"] == "", "phase"] = "hors_test"
    alerts.loc[alerts["posture"], "phase"] = "posture"
    return alerts


# ---------------------------------------------------------------- indicateurs
def mitre_match(alerts: pd.DataFrame, technique: str) -> bool:
    """Vrai si une alerte porte la technique testée ou sa technique parente (T1110.001 -> T1110)."""
    if not technique:
        return False
    parent = technique.split(".")[0]
    ids = alerts["mitre_ids"].fillna("").str.split(",").explode()
    return bool(ids.isin([technique, parent]).any())


def scenario_results(alerts: pd.DataFrame, scen: pd.DataFrame) -> pd.DataFrame:
    out = []
    for _, s in scen[scen["type"] == "test"].iterrows():
        a = alerts[(alerts["scenario_id"] == s["scenario_id"]) & ~alerts["posture"]]
        expected = [int(x) for x in s["expected_rules"].split(";") if x.strip().isdigit()]
        hits = a[a["rule_id"].isin(expected)]
        fired = sorted(set(hits["rule_id"]))
        custom = a[a["custom"]]
        first = hits["timestamp"].min()
        out.append({
            "scenario_id": s["scenario_id"],
            "mitre_id": s["mitre_id"],
            "technique": s["technique"],
            "description": s["description"],
            "expected_rules": ";".join(map(str, expected)),
            "fired_expected": ";".join(map(str, fired)),
            "detected": len(fired) > 0,
            "fully_detected": set(expected) <= set(fired),
            "ttd_seconds": round((first - s["start_utc"]).total_seconds(), 1) if pd.notna(first) else None,
            "alerts_in_window": len(a),
            "max_level_custom": int(custom["level"].max()) if len(custom) else 0,
            "max_level_in_run": int(a["level"].max()) if len(a) else 0,
            "mitre_match": mitre_match(hits, s["mitre_id"]),
        })
    return pd.DataFrame(out)


def control_results(alerts: pd.DataFrame, scen: pd.DataFrame) -> pd.DataFrame:
    """Campagne témoin (règles natives seules) : ce qu'un analyste aurait vu sans règles maison."""
    out = []
    for _, s in scen[scen["type"] == "test"].iterrows():
        a = alerts[(alerts["scenario_id"] == s["scenario_id"]) & ~alerts["posture"]]
        triage = a[a["level"] >= TRIAGE_LEVEL]
        top = a.sort_values(["level", "timestamp"], ascending=[False, True]).head(1)
        out.append({
            "scenario_id": s["scenario_id"],
            "max_level_builtin": int(a["level"].max()) if len(a) else 0,
            "builtin_triaged": len(triage) > 0,
            "builtin_ttd_seconds": round((triage["timestamp"].min() - s["start_utc"]).total_seconds(), 1) if len(triage) else None,
            "builtin_alerts": len(a),
            "top_builtin_rule": f"{int(top['rule_id'].iloc[0])} · {top['description'].iloc[0]}" if len(top) else "",
            "top_builtin_mitre": top["mitre_ids"].iloc[0] if len(top) else "",
            "builtin_mitre_match": mitre_match(a, s["mitre_id"]),
        })
    return pd.DataFrame(out)


def baseline_results(alerts: pd.DataFrame, scen: pd.DataFrame) -> pd.DataFrame:
    out = []
    for _, s in scen[scen["type"] == "baseline"].iterrows():
        a = alerts[(alerts["scenario_id"] == s["scenario_id"]) & ~alerts["posture"]]
        out.append({
            "scenario_id": s["scenario_id"],
            "description": s["description"],
            "alerts": len(a),
            "alerts_triage_level": int((a["level"] >= TRIAGE_LEVEL).sum()),
            "custom_false_positives": int(a["custom"].sum()),
            "max_level": int(a["level"].max()) if len(a) else 0,
            "rules": "; ".join(sorted(set(a["description"]))),
        })
    return pd.DataFrame(out)


def sca_summary(path: Path = DATA / "sca.json") -> dict:
    if not path.exists():
        return {}
    sca = json.loads(path.read_text())
    if not sca.get("policies"):
        return {}
    pol = sca["policies"][0]
    checks = pd.DataFrame(sca["checks"][pol["policy_id"]])

    def cis_section(comp):
        for c in comp or []:
            if c.get("key") == "cis":
                return c["value"].split(".")[0]
        return "?"

    names = {"1": "Configuration initiale", "2": "Services", "3": "Réseau",
             "4": "Pare-feu", "5": "Accès & authentification", "6": "Journalisation & audit",
             "7": "Maintenance système"}
    checks["section"] = checks["compliance"].apply(cis_section)
    by_sec = (checks.groupby(["section", "result"]).size().unstack(fill_value=0)
              .reindex(columns=["passed", "failed", "not applicable"], fill_value=0))
    sections = [{"section": f"{k}. {names.get(k, '')}".strip(), "passed": int(v["passed"]),
                 "failed": int(v["failed"]), "na": int(v["not applicable"])}
                for k, v in by_sec.iterrows()]
    failed = checks[checks["result"] == "failed"]
    examples = failed[["id", "title"]].head(12).to_dict("records")
    return {"policy": pol["name"], "score": pol["score"], "passed": pol["pass"],
            "failed": pol["fail"], "na": pol["invalid"], "sections": sections,
            "failed_examples": examples}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    DASH.mkdir(parents=True, exist_ok=True)
    alerts = attribute(load_alerts(), scen := load_scenarios())
    res = scenario_results(alerts, scen)
    ctrl_alerts_path = DATA / "builtin_only" / "alerts.json"
    ctrl_gt_path = ROOT / "tests" / "results" / "ground_truth_builtin_only.csv"
    if ctrl_alerts_path.exists() and ctrl_gt_path.exists():
        ctrl_scen = load_scenarios(ctrl_gt_path)
        ctrl = control_results(attribute(load_alerts(ctrl_alerts_path), ctrl_scen), ctrl_scen)
        res = res.merge(ctrl, on="scenario_id", how="left")
    else:
        print("Campagne témoin absente : comparaison règles natives ignorée.")
        for c in ["max_level_builtin", "builtin_triaged", "builtin_ttd_seconds", "builtin_alerts", "top_builtin_rule",
                  "top_builtin_mitre", "builtin_mitre_match"]:
            res[c] = None
    base = baseline_results(alerts, scen)
    sca = sca_summary()
    sca_after = sca_summary(DATA / "sca_apres.json") if (DATA / "sca_apres.json").exists() else {}

    alerts.to_csv(OUT / "alerts_enriched.csv", index=False)
    res.to_csv(OUT / "scenario_results.csv", index=False)
    base.to_csv(OUT / "baseline_results.csv", index=False)

    ops = alerts[~alerts["posture"] & (alerts["phase"] != "cleanup")]   # hors audit CIS et hors nettoyage
    tests = ops[ops["phase"] == "test"]
    level_dist = ops["level"].value_counts().sort_index()
    top_rules = (ops.groupby(["rule_id", "description"]).size().sort_values(ascending=False)
                 .head(10).reset_index(name="count"))

    metrics = {
        "generated_at": pd.Timestamp.now(tz="UTC").isoformat(timespec="seconds"),
        "period": {"start": scen["start_utc"].min().isoformat(), "end": scen["end_utc"].max().isoformat()},
        "totals": {
            "alerts": int(len(alerts)),
            "alerts_operational": int(len(ops)),
            "alerts_posture": int(alerts["posture"].sum()),
            "custom_alerts": int(ops["custom"].sum()),
        },
        "detection": {
            "scenarios": int(len(res)),
            "detected": int(res["detected"].sum()),
            "fully_detected": int(res["fully_detected"].sum()),
            "rate": round(100 * res["detected"].mean(), 1) if len(res) else 0,
            "builtin_triaged": int(res["builtin_triaged"].fillna(False).astype(bool).sum()),
            "builtin_rate": round(100 * res["builtin_triaged"].fillna(False).astype(bool).mean(), 1) if len(res) else 0,
            "mitre_match": int(res["mitre_match"].sum()),
            "builtin_mitre_match": int(res["builtin_mitre_match"].fillna(False).astype(bool).sum()),
            "builtin_ttd_median_s": (round(float(res["builtin_ttd_seconds"].dropna().median()), 2)
                                     if res["builtin_ttd_seconds"].notna().any() else None),
            "ttd_median_s": round(float(res["ttd_seconds"].median()), 2) if res["ttd_seconds"].notna().any() else None,
            "ttd_max_s": float(res["ttd_seconds"].max()) if res["ttd_seconds"].notna().any() else None,
        },
        "noise": {
            "baseline_alerts": int(base["alerts"].sum()) if len(base) else 0,
            "baseline_triage_alerts": int(base["alerts_triage_level"].sum()) if len(base) else 0,
            "custom_false_positives": int(base["custom_false_positives"].sum()) if len(base) else 0,
            "test_alerts": int(len(tests)),
            "test_alerts_triage": int((tests["level"] >= TRIAGE_LEVEL).sum()),
        },
        "level_distribution": {str(k): int(v) for k, v in level_dist.items()},
        "top_rules": top_rules.to_dict("records"),
        "scenarios": json.loads(res.to_json(orient="records")),
        "baseline": json.loads(base.to_json(orient="records")),
        "timeline": json.loads(ops[ops["level"] >= 5][["timestamp", "rule_id", "level", "description", "scenario_id", "custom"]]
                               .assign(timestamp=lambda d: d["timestamp"].dt.strftime("%H:%M:%S"))
                               .to_json(orient="records")),
        "sca": sca,
        "sca_after": sca_after,
    }
    (OUT / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=1, default=str))
    (DASH / "data.js").write_text("window.SOC_DATA = " + json.dumps(metrics, ensure_ascii=False, default=str) + ";\n")

    d = metrics["detection"]
    print(f"Alertes : {metrics['totals']['alerts']} (dont {metrics['totals']['alerts_posture']} de posture CIS)")
    print(f"Détection règles maison : {d['detected']}/{d['scenarios']} ({d['rate']} %), "
          f"règles natives seules (niveau >= {TRIAGE_LEVEL}) : {d['builtin_triaged']}/{d['scenarios']}")
    print(f"TTD médian : {d['ttd_median_s']} s, max : {d['ttd_max_s']} s")
    print(f"Faux positifs règles maison pendant l'activité normale : {metrics['noise']['custom_false_positives']}")
    print(res[["scenario_id", "mitre_id", "detected", "fired_expected", "ttd_seconds",
               "max_level_builtin", "max_level_custom"]].to_string(index=False))


if __name__ == "__main__":
    main()
