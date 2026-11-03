"""Exporte les alertes Wazuh et les résultats SCA du lab vers analysis/data/.

Usage (depuis la racine du projet, lab démarré) :
    python analysis/export_alerts.py --since 2026-11-03T02:40:00Z

Variables d'environnement optionnelles :
    INDEXER_URL (https://127.0.0.1:9200), INDEXER_USER, INDEXER_PASSWORD
    API_URL (https://127.0.0.1:55000), API_USER, API_PASSWORD
    AGENT_NAME (endpoint-ubuntu)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "analysis" / "data"
CA = ROOT / "lab" / "config" / "wazuh_indexer_ssl_certs" / "root-ca.pem"


def ssl_context() -> ssl.SSLContext:
    """Vérifie les certificats avec l'autorité du lab.

    Les certificats sont émis pour les noms internes Docker (wazuh.indexer...),
    on désactive donc uniquement la vérification du nom d'hôte quand on passe par localhost.
    """
    ctx = ssl.create_default_context(cafile=str(CA)) if CA.exists() else ssl.create_default_context()
    ctx.check_hostname = False
    # L'autorité auto-signée de Wazuh n'a pas l'extension "key usage" exigée par le
    # mode strict de Python >= 3.13 : on garde la vérification de chaîne, sans ce mode.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    if not CA.exists():
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_context() -> ssl.SSLContext:
    """L'API Wazuh (port 55000) génère son propre certificat auto-signé au démarrage :
    il n'est signé par aucune autorité, on ne peut donc pas le vérifier (lab local uniquement)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(url: str, *, method="GET", body=None, user=None, password=None, token=None, ctx=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif user:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, context=ctx or ssl_context(), timeout=60) as resp:
        raw = resp.read().decode()
    return json.loads(raw) if raw.strip().startswith(("{", "[")) else raw


def export_alerts(since: str, until: str | None, agent: str) -> list[dict]:
    url = os.getenv("INDEXER_URL", "https://127.0.0.1:9200")
    user = os.getenv("INDEXER_USER", "admin")
    pwd = os.getenv("INDEXER_PASSWORD", "SecretPassword")
    rng = {"gte": since}
    if until:
        rng["lte"] = until
    query = {
        "size": 10000,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"range": {"timestamp": rng}},
            {"term": {"agent.name": agent}},
        ]}},
    }
    res = request(f"{url}/wazuh-alerts-*/_search", method="POST", body=query, user=user, password=pwd)
    return [hit["_source"] for hit in res["hits"]["hits"]]


def export_sca(agent: str) -> dict:
    url = os.getenv("API_URL", "https://127.0.0.1:55000")
    user = os.getenv("API_USER", "wazuh-wui")
    pwd = os.getenv("API_PASSWORD", "MyS3cr37P450r.*-")
    ctx = api_context()
    token = request(f"{url}/security/user/authenticate?raw=true", method="POST", user=user, password=pwd, ctx=ctx)
    agents = request(f"{url}/agents?name={agent}", token=token, ctx=ctx)["data"]["affected_items"]
    if not agents:
        return {}
    agent_id = agents[0]["id"]
    policies = request(f"{url}/sca/{agent_id}", token=token, ctx=ctx)["data"]["affected_items"]
    out = {"agent_id": agent_id, "policies": policies, "checks": {}}
    for pol in policies:
        checks = request(f"{url}/sca/{agent_id}/checks/{pol['policy_id']}?limit=500", token=token, ctx=ctx)
        out["checks"][pol["policy_id"]] = checks["data"]["affected_items"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", help="début de la fenêtre (ISO 8601 UTC), obligatoire sauf avec --no-alerts")
    ap.add_argument("--until", help="fin de la fenêtre (ISO 8601 UTC)")
    ap.add_argument("--agent", default=os.getenv("AGENT_NAME", "endpoint-ubuntu"))
    ap.add_argument("--out", default=str(DATA), help="dossier de sortie (défaut : analysis/data)")
    ap.add_argument("--sca-file", default="sca.json", help="nom du fichier SCA (ex. sca_apres.json)")
    ap.add_argument("--no-alerts", action="store_true", help="n'exporter que les résultats SCA")
    args = ap.parse_args()
    if not args.no_alerts and not args.since:
        ap.error("--since est obligatoire pour exporter les alertes")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not args.no_alerts:
        alerts = export_alerts(args.since, args.until, args.agent)
        (out / "alerts.json").write_text(json.dumps(alerts, ensure_ascii=False, indent=1))
        print(f"{len(alerts)} alertes exportées -> {out / 'alerts.json'}")

    sca = export_sca(args.agent)
    (out / args.sca_file).write_text(json.dumps(sca, ensure_ascii=False, indent=1))
    n = sum(len(v) for v in sca.get("checks", {}).values())
    print(f"{n} contrôles SCA exportés -> {out / args.sca_file}")


if __name__ == "__main__":
    main()
