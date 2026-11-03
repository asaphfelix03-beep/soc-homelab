#!/usr/bin/env bash
# Exécute les scénarios de validation sur le poste surveillé et enregistre la
# "vérité terrain" (début/fin de chaque scénario, en UTC) dans results/ground_truth.csv.
#
# Tous les scénarios sont inoffensifs : ils reproduisent, sur TON propre poste de lab,
# des actions d'administration qu'un SOC doit savoir repérer (création de compte,
# tâche planifiée, modification de sudoers...). Rien ne sort du conteneur.
#
# Usage : ./tests/run_scenarios.sh            (depuis la racine du projet)
#         GAP=45 ./tests/run_scenarios.sh     (pause en secondes entre scénarios)
set -euo pipefail

EP="${ENDPOINT_CONTAINER:-soc-homelab-endpoint-ubuntu-1}"
GAP="${GAP:-45}"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/results"
GT="${GT_FILE:-$OUT_DIR/ground_truth.csv}"
mkdir -p "$OUT_DIR"
echo "scenario_id,start_utc,end_utc" > "$GT"

now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
as_root()     { docker exec "$EP" bash -c "$1"; }
as_analyste() { docker exec -u analyste "$EP" bash -c "$1"; }

run() {  # run <id> <description> <commande...>
  local id="$1" desc="$2"; shift 2
  local start; start=$(now)
  echo "[$start] $id - $desc"
  "$@"
  local end; end=$(now)
  echo "$id,$start,$end" >> "$GT"
}

wait_gap() { sleep "${1:-$GAP}"; }

PASS='Analyste2026!'

# ---------- Activité normale (référence pour mesurer le bruit) ----------
run B03 "Une faute de frappe sur sudo puis succès" as_analyste \
  "echo 'mauvais' | sudo -S -k true 2>/dev/null || true; echo '$PASS' | sudo -S -k true"
wait_gap
run B01 "Commandes sudo légitimes" as_analyste \
  "echo '$PASS' | sudo -S -k ls /root >/dev/null; echo '$PASS' | sudo -S -k cat /etc/hostname >/dev/null"
wait_gap
run B02 "Création d'un document utilisateur" as_analyste \
  "mkdir -p ~/rapports && echo 'Rapport hebdo' > ~/rapports/semaine45.txt && echo 'suite' >> ~/rapports/semaine45.txt"
wait_gap
run B04 "Modification d'un document existant" as_analyste \
  "echo 'Conclusion : RAS' >> ~/rapports/semaine45.txt"
wait_gap 60   # > 120 s depuis B03 pour ne pas mélanger les échecs d'authentification

# ---------- Scénarios mappés MITRE ATT&CK ----------
run S01 "T1110.001 - 6 mots de passe sudo erronés puis succès" as_analyste \
  "for i in 1 2 3 4 5 6; do echo 'Devine\$i' | sudo -S -k true 2>/dev/null || true; sleep 2; done; echo '$PASS' | sudo -S -k true"
wait_gap
run S02 "T1136.001 - création du compte support_it" as_root \
  "useradd -m -s /bin/bash support_it"
sleep 10
run S03 "T1098 - support_it ajouté au groupe sudo" as_root \
  "usermod -aG sudo support_it"
wait_gap
run S04 "T1548.003 - règle NOPASSWD dans sudoers.d" as_root \
  "echo 'support_it ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-support && chmod 440 /etc/sudoers.d/90-support"
wait_gap
run S05 "T1098.004 - clé SSH ajoutée" as_analyste \
  "rm -f /tmp/cle_test /tmp/cle_test.pub; ssh-keygen -t ed25519 -N '' -C 'test-lab' -f /tmp/cle_test -q && cat /tmp/cle_test.pub >> ~/.ssh/authorized_keys"
wait_gap
run S06 "T1053.003 - tâche cron" as_root \
  "echo '*/30 * * * * root /usr/bin/true # maintenance' > /etc/cron.d/maintenance"
wait_gap
run S07 "T1543.002 - service systemd" as_root \
  "printf '[Unit]\nDescription=Update helper\n[Service]\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/update-helper.service"
wait_gap
run S08 "T1036.005 - binaire au nom crédible dans /usr/sbin" as_root \
  "cp /usr/bin/true /usr/sbin/sshd-update"
wait_gap
run S09 "T1021.004 - PermitRootLogin activé" as_root \
  "sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config"
wait_gap
run S10 "T1571 - service sur un port non standard (2222)" as_root \
  "/usr/sbin/sshd -p 2222"
wait_gap 180  # la commande de surveillance des ports tourne toutes les 120 s

# ---------- Nettoyage (exclu de l'analyse du bruit) ----------
run C01 "Nettoyage du poste" as_root "
  # sshd réécrit le nom de son processus : on le retrouve par son port
  for pid in \$(ss -lntpH 'sport = :2222' | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u); do kill \$pid; done
  userdel -r support_it 2>/dev/null || true
  rm -f /etc/sudoers.d/90-support /etc/cron.d/maintenance /etc/systemd/system/update-helper.service /usr/sbin/sshd-update
  sed -i 's/^PermitRootLogin yes/#PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  sed -i '/test-lab$/d' /home/analyste/.ssh/authorized_keys
  rm -rf /home/analyste/rapports"
# La surveillance des ports tourne toutes les 120 s : on attend qu'elle constate la fermeture
# du port 2222, sinon l'alerte tomberait dans la campagne suivante.
wait_gap 150

echo "Terminé. Vérité terrain : $GT"
