#!/usr/bin/env bash
# Campagne TÉMOIN : rejoue exactement les mêmes scénarios avec les règles
# personnalisées désactivées, pour mesurer ce que les règles natives de Wazuh
# détectent seules. Les règles personnalisées sont restaurées à la fin.
#
# Usage : ./tests/run_control.sh   (depuis la racine du projet, après run_scenarios.sh)
set -euo pipefail

MANAGER="${MANAGER_CONTAINER:-soc-homelab-wazuh.manager-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULES="/var/ossec/etc/rules/local_rules.xml"

reload_manager() {
  docker exec "$MANAGER" bash -c "chown wazuh:wazuh $RULES && /var/ossec/bin/wazuh-control restart >/dev/null 2>&1"
  # Pas de "cmd | grep -q" ici : avec pipefail, grep -q ferme le tube trop tôt (SIGPIPE)
  # et la boucle ne se termine jamais. On capture la sortie d'abord.
  local out
  until out=$(docker exec "$MANAGER" /var/ossec/bin/wazuh-control status || true) && [[ "$out" == *"wazuh-analysisd is running"* ]]; do sleep 2; done
  until out=$(docker exec "$MANAGER" /var/ossec/bin/agent_control -l || true) && grep -Eq 'endpoint-ubuntu.*Active$' <<<"$out"; do sleep 3; done
  sleep 30   # laisse l'agent se reconnecter complètement
}

restore() {
  echo "Restauration des règles personnalisées..."
  docker cp "$ROOT/detection/rules/local_rules.xml" "$MANAGER:$RULES"
  reload_manager
}
trap restore EXIT

echo "Désactivation des règles personnalisées..."
docker exec -i "$MANAGER" bash -c "cat > $RULES" <<'EOF'
<!-- Campagne témoin : aucune règle personnalisée active -->
<group name="local,">
  <rule id="100199" level="0">
    <match>^__regle_temoin_jamais_declenchee__$</match>
    <description>Règle vide (campagne témoin)</description>
  </rule>
</group>
EOF
reload_manager

GT_FILE="$ROOT/tests/results/ground_truth_builtin_only.csv" "$ROOT/tests/run_scenarios.sh"
