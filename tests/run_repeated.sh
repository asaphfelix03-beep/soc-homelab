#!/usr/bin/env bash
# Répète la campagne de validation N fois pour mesurer la STABILITÉ des détections
# et la dispersion des temps de détection.
#   Campagne 1 -> tests/results/ground_truth.csv (campagne de référence)
#   Campagnes 2..N -> tests/results/repetitions/run_<k>.csv
#
# Usage : RUNS=3 ./tests/run_repeated.sh   (depuis la racine du projet)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${RUNS:-3}"
PAUSE="${PAUSE:-30}"    # le nettoyage de run_scenarios.sh attend déjà la fermeture du port 2222
mkdir -p "$ROOT/tests/results/repetitions"

for k in $(seq 1 "$RUNS"); do
  if [ "$k" -eq 1 ]; then gt="$ROOT/tests/results/ground_truth.csv"; else gt="$ROOT/tests/results/repetitions/run_$k.csv"; fi
  echo "===== Campagne $k/$RUNS -> $gt"
  GT_FILE="$gt" "$ROOT/tests/run_scenarios.sh"
  [ "$k" -lt "$RUNS" ] && { echo "Pause de $PAUSE s avant la campagne suivante"; sleep "$PAUSE"; }
done
echo "Toutes les campagnes sont terminées."
