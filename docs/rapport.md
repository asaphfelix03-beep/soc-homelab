# Rapport : SOC Homelab Wazuh

**Auteur :** Ojewumi Asaph Felix, L3 Cybersécurité & IA, ESATIC
**Date des campagnes :** 3 novembre 2026
**Outils :** Wazuh 4.14.9 (manager, indexer, dashboard), Docker, Ubuntu 24.04, Python 3 / pandas, Chart.js

## 1. Objectif

Répondre à une question concrète d'analyste SOC : **sur un poste Linux, quelles techniques d'attaque courantes sont réellement détectées, en combien de temps, et avec combien de bruit ?** Puis mesurer ce que des règles de détection personnalisées apportent par rapport à la configuration native de Wazuh.

## 2. Environnement

| Composant | Rôle |
|---|---|
| `wazuh.manager` | Analyse les événements, applique les règles natives + `local_rules.xml` |
| `wazuh.indexer` | Stocke les alertes (OpenSearch), interrogé par l'API pour l'export |
| `wazuh.dashboard` | Interface d'investigation (`https://localhost:8443`) |
| `endpoint-ubuntu` | Poste surveillé : agent Wazuh avec FIM temps réel, collecte d'`auth.log` / `syslog` / `dpkg.log`, surveillance des ports, SCA (benchmark CIS) |

Tout tourne en local dans Docker, ports liés à `127.0.0.1`. Les communications entre composants sont chiffrées en TLS avec une autorité de certification générée pour le lab.

## 3. Méthodologie

### 3.1 Scénarios

Dix scénarios reproduisent les **traces** laissées par dix techniques MITRE ATT&CK, avec des actions d'administration inoffensives sur le poste du lab (création de compte, tâche cron, clé SSH, etc.). Trois activités normales (B01 à B03) servent de référence pour mesurer le bruit. Le détail est dans [`tests/scenarios.csv`](../tests/scenarios.csv).

### 3.2 Vérité terrain et attribution

Le script [`tests/run_scenarios.sh`](../tests/run_scenarios.sh) horodate le début et la fin de chaque scénario (UTC, à la milliseconde), avec 45 s de pause entre deux scénarios. Une alerte est attribuée au scénario dont la fenêtre la contient : du début du scénario jusqu'au début du suivant.

### 3.3 Indicateurs

| Indicateur | Définition |
|---|---|
| **Détecté** | Une alerte de niveau ≥ 7 (seuil de triage) est levée dans la fenêtre du scénario |
| **Bonne technique** | Une alerte de la fenêtre porte l'identifiant MITRE testé, ou sa technique parente |
| **TTD** | Temps entre le début du scénario et la première alerte attendue |
| **Faux positif** | Alerte de mes règles pendant une activité normale (B01 à B03) |

### 3.4 Test A/B

La campagne est exécutée **deux fois sur le même poste** :

- **A, officielle :** règles natives + règles personnalisées ;
- **B, témoin :** règles personnalisées désactivées ([`tests/run_control.sh`](../tests/run_control.sh)).

Seule différence : le fichier `local_rules.xml`. On mesure donc l'apport réel des règles, et non une estimation.

## 4. Résultats

### 4.1 Détection par technique

| Scénario | Technique | A : règle déclenchée (niveau) | TTD (s) | B : meilleure alerte native (niveau) |
|---|---|---|---|---|
| S01 | T1110.001 Password Guessing | 100113 + 100114 (13) | 16,9 | 5503 PAM: User login failed (5) |
| S02 | T1136.001 Create Local Account | 5902 native (8) | 0,5 | 5902 New user added (8) |
| S03 | T1098 Account Manipulation | 100112 corrélation (14) | 0,4 | 550 Integrity checksum changed (7) |
| S04 | T1548.003 Sudo | 100100 (12) | 0,1 | 554 File added to the system (5) |
| S05 | T1098.004 SSH Authorized Keys | 100101 (10) | 0,1 | 550 Integrity checksum changed (7) |
| S06 | T1053.003 Cron | 100102 (10) | 0,1 | 554 File added to the system (5) |
| S07 | T1543.002 Systemd Service | 100103 (10) | 0,1 | 554 File added to the system (5) |
| S08 | T1036.005 Match Legitimate Name | 100104 (12) | 0,1 | 554 File added to the system (5) |
| S09 | T1021.004 SSH | 100106 (8) | 0,2 | 550 Integrity checksum changed (7) |
| S10 | T1571 Non-Standard Port | 100116 (10) | 106,4 | 533 Listened ports changed (7) |

### 4.2 Synthèse

| Indicateur | A : natives + personnalisées | B : natives seules |
|---|---|---|
| Techniques détectées (niveau ≥ 7) | **10/10** | 5/10 |
| Alertes portant la bonne technique MITRE | **10/10** | 2/10 |
| TTD médian | 0,15 s | 0,1 s (sur les 5 détectées) |
| TTD maximal | 106,4 s (S10) | – |
| Alertes de mes règles pendant l'activité normale | **0** sur 13 alertes | – |

### 4.3 Lecture

- **Les règles natives voient presque tout, mais elles ne disent pas quoi.** Dans les 10 cas, la campagne témoin lève bien une alerte, mais générique (« File added to the system », « Integrity checksum changed »). L'analyste doit ouvrir l'alerte et lire le chemin du fichier pour comprendre qu'il s'agit d'une tâche cron ou d'une règle sudoers. En niveau 5, ces alertes passent sous le seuil de triage et seraient noyées dans le bruit.
- **Le nom de la menace et la technique MITRE accélèrent le triage.** Avec les règles personnalisées, chaque alerte dit ce qui se passe (« [SOC] Tâche cron créée : /etc/cron.d/maintenance ») et porte la bonne technique, ce qui permet de mesurer la couverture ATT&CK.
- **La corrélation transforme deux signaux faibles en un incident.** S03 : sans corrélation, on voit une modification de `/etc/group` (niveau 7). Avec la règle 100112, on voit « compte créé puis promu administrateur en moins de 10 minutes » (niveau 14). S01 : six échecs de niveau 5 deviennent une alerte de niveau 10 (100113), puis la connexion réussie qui suit monte en niveau 13 (100114).
- **Le temps de détection est quasi instantané pour le FIM temps réel** (0,1 s). S10 dépend de la fréquence de la commande de surveillance des ports (120 s) : 106 s ici. En production, il faudrait choisir entre réactivité et charge.

### 4.4 Bruit

Les trois activités normales ont produit 13 alertes, toutes de niveau ≤ 5, **sans aucune alerte de mes règles**. En revanche, dans la campagne témoin, la modification d'un document existant dans `/home/analyste` a levé une alerte native **550 de niveau 7** : un faux positif potentiel pour l'analyste. Dans la campagne officielle, ce fichier venait d'être créé, d'où une alerte 554 de niveau 5.

### 4.5 Posture CIS

| | Avant | Après `hardening/harden.sh` |
|---|---|---|
| Score SCA (CIS Ubuntu 24.04 v1.0.0) | **48 %** | **62 %** |
| Contrôles réussis | 100 | 130 |
| Contrôles échoués | 107 | 77 |
| Non applicables | 72 | 72 |

Trente contrôles ont été corrigés, sans aucune régression : SSH, cron, bannières, PAM, politique de mots de passe, journaux, core dumps et restriction de `su`. Les échecs restants relèvent surtout de ce qu'un conteneur ne permet pas : partitions séparées, pare-feu, `auditd`, AppArmor et paramètres réseau du noyau. Trois contrôles ciblés restent en échec : 2.4.1.1 (pas de systemd dans le conteneur), 2.4.2.1 (paquet `at` absent) et 5.2.3. Pour ce dernier, la directive `Defaults logfile=` est bien présente, mais le contrôle échoue toujours. La cause n'est pas élucidée ; l'expression régulière de la politique est suspectée.

## 5. Problèmes rencontrés

Neuf problèmes réels ont été trouvés et corrigés pendant le projet : syntaxe des règles de fréquence, perte de la surveillance FIM après remplacement d'un fichier, commande absente de l'image, scripts qui se tuaient eux-mêmes, etc. Ils sont détaillés dans [regles-detection.md](regles-detection.md#leçons-apprises-problèmes-réels-rencontrés).

Le plus instructif est le n°6 : tout fonctionnait lors de la **première** campagne, sur un poste neuf. C'est la seconde campagne qui a montré que la surveillance temps réel d'un fichier isolé disparaît dès que ce fichier est remplacé. **Une détection se valide en la testant plusieurs fois.**

Les chiffres publiés viennent de campagnes rejouées **après** toutes les corrections, sur un poste neuf.

## 6. Limites

- Un seul poste, Linux, en conteneur. Pas de Windows, pas de réseau d'entreprise.
- Les scénarios reproduisent des traces d'attaque avec des actions légitimes. Ils ne couvrent pas les techniques d'évasion d'un vrai attaquant (désactivation de l'agent, effacement des journaux, exécution en mémoire).
- Une seule exécution de chaque campagne finale : les temps de détection varient d'une exécution à l'autre, notamment S10 (entre 0 et 120 s selon le moment).
- Trois activités normales : c'est trop peu pour estimer un taux de faux positifs en production.

## Pistes d'amélioration

1. **Réduire le bruit FIM sur `/home`** : une règle qui abaisse à 3 le niveau des modifications de documents (`.txt`, `.docx`, etc.), tout en gardant les fichiers sensibles (`.ssh/`, `.bashrc`, `.profile`) au-dessus du seuil.
2. **Corréler 100104 avec `dpkg`** : ignorer les nouveaux binaires déposés pendant une installation de paquet légitime (règle 2902).
3. **Ajouter `auditd`** (sur une VM) pour voir les commandes exécutées, et pas seulement les fichiers modifiés.
4. **Poste Windows avec Sysmon** : voir [extension-windows.md](extension-windows.md).
5. **Réponse active** : bloquer automatiquement un compte après la règle 100114.
6. **Répéter chaque campagne 5 fois** pour donner des intervalles de temps de détection plutôt qu'une valeur unique.

## 7. Reproduire

Voir [installation.md](installation.md). Toutes les données brutes sont dans [`analysis/data/`](../analysis/data/), les résultats dans [`analysis/output/`](../analysis/output/).
