# Installation et utilisation du lab

Ce guide permet de reproduire tout le projet sur ta machine : déploiement de Wazuh, campagne de tests, analyse et dashboard.

## Prérequis

| Élément | Minimum |
|---|---|
| RAM | 8 Go (16 Go conseillés : l'indexer réserve 1 Go à lui seul) |
| Disque | 15 Go libres |
| Logiciels | Docker + Docker Compose v2, Git, Python 3.10+ |
| Windows | Docker Desktop avec le backend **WSL 2**. Lance toutes les commandes de ce guide depuis un terminal **Ubuntu (WSL)** : les scripts sont en bash et utilisent `date` GNU (ils ne marchent ni dans PowerShell ni sous macOS sans `coreutils`) |

## 1. Récupérer le projet

```bash
git clone https://github.com/asaphfelix03-beep/soc-homelab.git
cd soc-homelab
```

## 2. Régler le noyau pour l'indexer

L'indexer (OpenSearch) refuse de démarrer si `vm.max_map_count` est trop bas.

Linux :

```bash
sudo sysctl -w vm.max_map_count=262144
```

Windows (Docker Desktop / WSL 2), dans PowerShell :

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

## 3. Générer les certificats TLS

Les composants Wazuh communiquent en TLS. Les certificats sont générés localement et **ne sont jamais publiés** (voir `.gitignore`).

```bash
cd lab
docker compose -f generate-indexer-certs.yml run --rm generator
```

## 4. Démarrer la stack

```bash
docker compose up -d --build
```

Le premier démarrage prend 2 à 5 minutes. Le dashboard est ensuite accessible sur **https://localhost:8443** (identifiant `admin`, mot de passe `SecretPassword`). Le navigateur affiche un avertissement : le certificat est auto-signé, c'est normal pour un lab.

Vérifie que l'agent du poste est connecté :

```bash
docker exec soc-homelab-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

> **Changer les mots de passe.** Les valeurs par défaut sont celles de la documentation Wazuh. Le lab n'écoute que sur `127.0.0.1`, mais si tu l'exposes un jour sur un réseau, change-les en suivant la [documentation officielle](https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html).

## 5. Lancer la campagne de validation

Attends environ 1 minute après la connexion de l'agent (le temps du scan FIM initial), puis :

```bash
cd ..
./tests/run_scenarios.sh
```

La campagne dure environ 15 minutes. Elle écrit la vérité terrain dans `tests/results/ground_truth.csv` et remet le poste dans son état initial à la fin.

## 6. Exporter et analyser

```bash
pip install -r requirements.txt
python analysis/export_alerts.py --since 2026-11-03T03:08:00Z --until 2026-11-03T03:25:00Z
python analysis/analyze.py
```

Remplace les dates par la fenêtre de ta propre campagne : la première et la dernière ligne de `ground_truth.csv`.

## 7. Ouvrir le dashboard

```bash
cd docs/dashboard
python -m http.server 8000
```

Puis ouvre http://localhost:8000. Pour le publier, active GitHub Pages sur le dossier `docs/` du dépôt.

## 8. Bonus : durcissement CIS

```bash
docker exec -i soc-homelab-endpoint-ubuntu-1 bash < hardening/harden.sh
docker exec soc-homelab-endpoint-ubuntu-1 /var/ossec/bin/wazuh-control restart   # relance le scan SCA
```

Après 1 à 2 minutes, réexporte les résultats SCA et compare le score.

## Arrêter et nettoyer

```bash
cd lab
docker compose down        # arrête le lab, conserve les données
docker compose down -v     # supprime aussi toutes les alertes et la configuration
```

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| L'indexer redémarre en boucle | `vm.max_map_count` trop bas | Étape 2 |
| Le dashboard affiche « Wazuh API not reachable » | Le manager démarre encore | Attendre 2 minutes |
| `error setting rlimit` au démarrage | Environnement qui interdit `memlock` illimité (certains clouds) | Supprimer les blocs `memlock` du `docker-compose.yml` |
| L'agent n'apparaît pas | Manager pas encore prêt lors de l'enrôlement | `docker compose restart endpoint-ubuntu` |
| `apt` échoue pendant le build derrière un proxy d'entreprise | Proxy HTTPS uniquement | `docker build --build-arg APT_HTTPS=1 --secret id=extra_ca,src=<ca.pem> ...` |
