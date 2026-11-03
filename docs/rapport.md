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

Dix scénarios reproduisent les **traces** laissées par dix techniques MITRE ATT&CK, avec des actions d'administration inoffensives sur le poste du lab (création de compte, tâche cron, clé SSH, etc.). Quatre activités normales (B01 à B04 : sudo légitime, faute de frappe, création puis modification d'un document) servent de référence pour mesurer le bruit. Le détail est dans [`tests/scenarios.csv`](../tests/scenarios.csv).

### 3.2 Vérité terrain et attribution

Le script [`tests/run_scenarios.sh`](../tests/run_scenarios.sh) horodate le début et la fin de chaque scénario (UTC, à la milliseconde), avec 45 s de pause entre deux scénarios. Une alerte est attribuée au scénario dont la fenêtre la contient : du début du scénario jusqu'au début du suivant.

### 3.3 Indicateurs

| Indicateur | Définition |
|---|---|
| **Détecté** | Une alerte de niveau ≥ 7 (seuil de triage) est levée dans la fenêtre du scénario |
| **Bonne technique** | Une alerte de la fenêtre porte l'identifiant MITRE testé, ou sa technique parente |
| **TTD** | Temps entre le début du scénario et la première alerte attendue |
| **Faux positif** | Alerte de mes règles **de niveau ≥ 7** pendant une activité normale (B01 à B04). Les alertes de niveau 3 de la règle anti-bruit 100120 sont journalisées mais pas triées : ce ne sont pas des faux positifs |

### 3.4 Test A/B

La campagne est exécutée **deux fois sur le même poste** :

- **A, officielle :** règles natives + règles personnalisées ;
- **B, témoin :** règles personnalisées désactivées ([`tests/run_control.sh`](../tests/run_control.sh)).

Seule différence : le fichier `local_rules.xml`. On mesure donc l'apport réel des règles, et non une estimation.

### 3.5 Répétition

La campagne A est jouée **3 fois de suite** sur le même poste ([`tests/run_repeated.sh`](../tests/run_repeated.sh)), avec 150 s de pause entre deux campagnes. Chaque campagne remet le poste dans son état initial. On vérifie ainsi que les détections sont **stables** (un des bugs trouvés n'apparaissait qu'à la 2ᵉ campagne) et on obtient une fourchette de temps de détection au lieu d'une valeur unique.

## 4. Résultats

### 4.1 Détection par technique

A : natives + personnalisées, **3 campagnes**. B : natives seules (campagne témoin).

| Scénario | Technique | A : règle déclenchée (niveau) | A : stabilité | A : TTD médian (min–max) | B : meilleure alerte native (niveau) |
|---|---|---|---|---|---|
| S01 | T1110.001 Password Guessing | 100113 + 100114 (13) | 3/3 | 17,1 s (16,8 s – 17,5 s) | 5503 PAM: User login failed. (5) |
| S02 | T1136.001 Local Account | 5902 native (8) | 3/3 | 1,2 s (1,1 s – 2,0 s) | 5902 New user added to the system. (8) |
| S03 | T1098 Account Manipulation | 100112 (14) | 3/3 | 1,1 s (0,90 s – 1,9 s) | 550 Integrity checksum changed. (7) |
| S04 | T1548.003 Sudo and Sudo Caching | 100100 (12) | 3/3 | 0,10 s (identique sur les 3) | 554 File added to the system. (5) |
| S05 | T1098.004 SSH Authorized Keys | 100101 (10) | 3/3 | 0,10 s (identique sur les 3) | 554 File added to the system. (5) |
| S06 | T1053.003 Cron | 100102 (10) | 3/3 | 0,10 s (identique sur les 3) | 554 File added to the system. (5) |
| S07 | T1543.002 Systemd Service | 100103 (10) | 3/3 | 0,10 s (identique sur les 3) | 554 File added to the system. (5) |
| S08 | T1036.005 Match Legitimate Resource Name or Location | 100104 (12) | 3/3 | 0,10 s (identique sur les 3) | 554 File added to the system. (5) |
| S09 | T1021.004 SSH | 100106 (8) | 3/3 | 0,10 s (identique sur les 3) | 550 Integrity checksum changed. (7) |
| S10 | T1571 Non-Standard Port | 100116 (10) | 3/3 | 53,3 s (47,1 s – 60,1 s) | 533 Listened ports status (netstat) changed (new port opened or closed). (7) |

### 4.2 Synthèse

| Indicateur | A : natives + personnalisées | B : natives seules |
|---|---|---|
| Techniques détectées (niveau ≥ 7) | **10/10**, à chacune des 3 campagnes | 4/10 |
| Alertes portant la bonne technique MITRE | **10/10** | 2/10 |
| TTD médian, toutes campagnes | 0,10 s | 0,10 s (sur les 4 détectées) |
| TTD médian, scénarios FIM (S04 à S09) | 0,10 s | – |
| TTD maximal | 60,1 s (S10) | – |
| Faux positifs pendant l'activité normale (niveau ≥ 7) | **0** sur 3 campagnes | 1 (alerte native sur un document modifié) |

### 4.3 Lecture

- **Les règles natives voient presque tout, mais elles ne disent pas quoi.** Dans les 10 cas, la campagne témoin lève une alerte. Seules S01 (échecs PAM) et S02 (création de compte) portent la bonne technique ; les autres sont génériques (« File added to the system », « Integrity checksum changed »). L'analyste doit ouvrir l'alerte et lire le chemin du fichier pour comprendre qu'il s'agit d'une tâche cron ou d'une règle sudoers. En niveau 5, ces alertes passent sous le seuil de triage.
- **Le nom de la menace et la technique MITRE accélèrent le triage.** Avec les règles personnalisées, chaque alerte dit ce qui se passe (« [SOC] Tâche cron créée ou modifiée : /etc/cron.d/maintenance ») et porte la bonne technique, ce qui permet de mesurer la couverture ATT&CK.
- **La corrélation transforme des signaux faibles en incident.** S03 : sans corrélation, on voit une modification de `/etc/group` (niveau 7). Avec la règle 100112 : « compte créé puis promu administrateur en moins de 10 minutes » (niveau 14). S01 : six échecs de niveau 5 deviennent une alerte de niveau 10 (100113), puis la connexion réussie qui suit monte au niveau 13 (100114).
- **Le résultat natif dépend de l'état du poste, pas mes règles.** S05 : sur un poste neuf, `authorized_keys` n'existe pas encore, donc sa création donne la règle native 554 (niveau 5, sous le seuil). Si le fichier existait déjà, sa modification donnerait 550 (niveau 7). La règle 100101 couvre les deux cas, au niveau 10.
- **Les détections sont stables.** Les 10 techniques sont détectées à chacune des 3 campagnes. Le FIM temps réel répond en 0,10 s à chaque fois. S10 varie de 47,1 s à 60,1 s, car les ports sont contrôlés toutes les 120 s : le délai dépend du moment où tombe le prochain contrôle.

### 4.4 Bruit

Activité normale de la campagne de référence (A) et de la campagne témoin (B) :

| Activité | A : alertes | A : niveau ≥ 7 | A : ramenées au niveau 3 (100120) | B : niveau ≥ 7 |
|---|---|---|---|---|
| B03 Une seule faute de frappe sur le mot de passe sudo | 6 | 0 | 0 | 0 |
| B01 Commandes sudo légitimes de l'administrateur | 6 | 0 | 0 | 0 |
| B02 Création d'un document dans /home/analyste | 1 | 0 | 1 | 0 |
| B04 Modification d'un document existant dans /home/analyste | 1 | 0 | 1 | 1 |

Sans mes règles, la modification d'un document existant (B04) lève une alerte native de niveau ≥ 7 (550, « Integrity checksum changed »), qu'un analyste devrait traiter. Avec la règle 100120, elle est journalisée au niveau 3 et n'atteint plus le seuil de triage. Les fichiers sensibles du dossier personnel (`.ssh/authorized_keys`, `.bashrc`) restent signalés : cela a été vérifié en conditions réelles avant les campagnes.

### 4.5 Posture CIS

| | Avant | Après `hardening/harden.sh` |
|---|---|---|
| Score SCA (CIS Ubuntu 24.04 v1.0.0) | **48 %** | **62 %** |
| Contrôles réussis | 100 | 130 |
| Contrôles échoués | 107 | 77 |
| Non applicables | 72 | 72 |

30 contrôles ont été corrigés en un seul passage du script, sans aucune régression : SSH, cron, bannières, PAM, politique de mots de passe, journaux, core dumps et restriction de `su`. Les échecs restants relèvent surtout de ce qu'un conteneur ne permet pas : partitions séparées, pare-feu, `auditd`, AppArmor et paramètres réseau du noyau. Trois contrôles ciblés restent en échec : 2.4.1.1 (pas de systemd dans le conteneur), 2.4.2.1 (paquet `at` absent) et 5.2.3. Pour ce dernier, la directive `Defaults logfile=` est bien présente, mais le contrôle échoue toujours. La cause n'est pas élucidée ; l'expression régulière de la politique est suspectée.

## 5. Problèmes rencontrés

Onze problèmes réels ont été trouvés et corrigés pendant le projet : syntaxe des règles de fréquence, perte de la surveillance FIM après remplacement d'un fichier, commande absente de l'image, scripts qui se tuaient eux-mêmes, etc. Ils sont détaillés dans [regles-detection.md](regles-detection.md#leçons-apprises-problèmes-réels-rencontrés).

Le plus instructif est le n°6 : tout fonctionnait lors de la **première** campagne, sur un poste neuf. C'est la seconde campagne qui a montré que la surveillance temps réel d'un fichier isolé disparaît dès que ce fichier est remplacé. **Une détection se valide en la testant plusieurs fois.**

Les chiffres publiés viennent de campagnes rejouées **après** toutes les corrections, sur un poste neuf.

## 6. Limites

- Un seul poste, Linux, en conteneur. Pas de Windows, pas de réseau d'entreprise.
- Les scénarios reproduisent des traces d'attaque avec des actions légitimes. Ils ne couvrent pas les techniques d'évasion d'un vrai attaquant (désactivation de l'agent, effacement des journaux, exécution en mémoire).
- Trois campagnes répétées montrent des détections stables, mais c'est encore un petit échantillon. Les temps de S10 dépendent du cycle de 120 s de la surveillance des ports.
- Quatre activités normales : c'est trop peu pour estimer un taux de faux positifs en production, qui demanderait des semaines d'activité réelle.

## Pistes d'amélioration

Réalisées depuis la première version :

- ✅ **Bruit FIM sur `/home` réduit** : règle 100120, vérifiée en conditions réelles (documents au niveau 3, fichiers sensibles toujours signalés).
- ✅ **Campagnes répétées** : 3 campagnes identiques, avec la fourchette des temps de détection.

À faire :

1. **Poste Windows avec Sysmon** : voir [extension-windows.md](extension-windows.md). C'est la limite la plus importante.
2. **Corréler 100104 avec `dpkg`** : ignorer les nouveaux binaires déposés pendant une installation de paquet légitime (règle 2902).
3. **Détecter les suppressions massives** (T1485 Data Destruction) : une règle de fréquence sur les suppressions de documents, que la règle 100120 laisse volontairement visibles.
4. **Ajouter `auditd`** (sur une VM) pour voir les commandes exécutées, et pas seulement les fichiers modifiés.
5. **Réponse active** : bloquer automatiquement un compte après la règle 100114.

## 7. Reproduire

**Reproductibilité vérifiée.** Après publication, le lab a été entièrement supprimé (conteneurs, volumes, image), puis redéployé à partir d'un clone neuf du dépôt GitHub en suivant [installation.md](installation.md). Résultats : 10/10 techniques détectées par les mêmes règles aux mêmes niveaux, 0 faux positif, et un score CIS de 48 % → 62 % avec un seul passage de `harden.sh`. Les indicateurs recalculés depuis les données publiées sont identiques au commit (pandas 3.0.5 et 3.1.0).


Voir [installation.md](installation.md). Toutes les données brutes sont dans [`analysis/data/`](../analysis/data/), les résultats dans [`analysis/output/`](../analysis/output/).
