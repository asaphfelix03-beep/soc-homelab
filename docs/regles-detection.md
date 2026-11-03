# Règles de détection personnalisées

Fichier source : [`detection/rules/local_rules.xml`](../detection/rules/local_rules.xml). Plage d'identifiants : 100100 à 100199.

## Catalogue

| ID | Niveau | Technique MITRE | Source | Ce qui est détecté |
|---|---|---|---|---|
| 100100 | 12 | T1548.003 Sudo and Sudo Caching | FIM | Création ou modification de `/etc/sudoers` ou `/etc/sudoers.d/*` |
| 100101 | 10 | T1098.004 SSH Authorized Keys | FIM | Ajout ou modification d'un fichier `authorized_keys` |
| 100102 | 10 | T1053.003 Cron | FIM | Tâche planifiée dans `/etc/cron.d`, `/etc/crontab` ou les crontabs utilisateur |
| 100103 | 10 | T1543.002 Systemd Service | FIM | Nouveau fichier `.service` dans `/etc/systemd/system` |
| 100104 | 12 | T1036.005 Match Legitimate Name or Location | FIM | Nouveau binaire déposé dans `/usr/bin` ou `/usr/sbin` |
| 100106 | 8 | T1021.004 SSH | FIM | Modification de `/etc/ssh/sshd_config` |
| 100110 | 12 | T1098 Account Manipulation | auth.log | Utilisateur ajouté au groupe `sudo` ou `admin` (`usermod`, `gpasswd`) |
| 100112 | 14 | T1136.001 + T1098 | Corrélation | Compte **créé puis promu administrateur** en moins de 10 minutes |
| 100113 | 10 | T1110.001 Password Guessing | Corrélation | 5 échecs d'authentification PAM sur le même compte en 2 minutes |
| 100114 | 13 | T1110.001 + T1078 | Corrélation | **Succès** d'authentification moins de 5 minutes après la règle 100113 |
| 100116 | 10 | T1571 Non-Standard Port | Commande | Nouveau port en écoute sur le poste (sortie de `ss -lntu` modifiée) |

### Pourquoi des règles personnalisées ?

Les règles natives de Wazuh voient bien ces événements, mais de façon **générique**. Une tâche cron créée donne « File added to the system » (niveau 5), sans technique MITRE ni contexte. L'analyste doit lire le chemin du fichier pour comprendre. Les règles personnalisées :

1. **nomment le risque** (« Tâche cron créée »), ce qui accélère le triage ;
2. **montent le niveau** au-dessus du seuil de triage (7) quand le risque le justifie ;
3. **ajoutent la technique MITRE ATT&CK**, ce qui permet de mesurer la couverture ;
4. **corrèlent** plusieurs événements anodins en un seul incident (100112, 100114).

## Méthode de validation

1. **Test unitaire** de chaque règle sur journaux avec `wazuh-logtest` (rejoue une ligne de log dans le moteur).
2. **Répétition générale** de la campagne complète, pour trouver les problèmes d'intégration.
3. **Campagne officielle** sur une installation propre, avec vérité terrain horodatée.
4. **Campagne témoin** identique, avec les règles personnalisées désactivées, pour mesurer leur apport réel.
5. **Mesure du bruit** : trois activités normales d'administration ne doivent déclencher aucune règle personnalisée.

## Leçons apprises (problèmes réels rencontrés)

| # | Problème observé | Cause | Correction |
|---|---|---|---|
| 1 | La règle 100113 (5 échecs) ne se déclenchait **jamais**, même après 15 échecs | Dans Wazuh 4.14, `if_matched_group` ne comptait pas ces événements PAM ; `if_matched_sid` fonctionne | Passage à `<if_matched_sid>5503</if_matched_sid>` : la règle 5503 couvre déjà sudo, su, login et SSH via PAM |
| 2 | Avec `<same_field>dstuser</same_field>`, toujours aucune alerte | `dstuser` est un champ **statique** du décodeur : `same_field` ne s'applique qu'aux champs dynamiques. `same_dstuser` n'existe pas (le manager refuse de démarrer) | `<same_user />`, l'option utilisée par les règles natives |
| 3 | La corrélation « succès après échecs » (100114) ratait le premier sudo | Le premier sudo d'un utilisateur est classé 5403 (« First time user executed sudo »), pas 5402 | Ajout de 5403 à la liste des règles de succès |
| 4 | La surveillance des ports (100116) restait muette | La commande `ss` n'existe pas dans l'image Ubuntu minimale : l'agent exécutait une commande en erreur, sans alerte | Ajout du paquet `iproute2` à l'image |
| 5 | Le script de nettoyage s'arrêtait avec le code 143 | `pkill -f 'sshd -p 2222'` reconnaissait **sa propre ligne de commande** et tuait le shell qui l'exécutait | Ne plus chercher par nom (voir 7) |
| 6 | Lors d'une 2ᵉ campagne, les modifications de `sshd_config` et `/etc/passwd` n'étaient **plus vues** en temps réel | `sed -i`, `useradd` et `visudo` remplacent le fichier par un nouveau (nouvel inode). La surveillance temps réel d'un **fichier isolé** est perdue après le premier remplacement ; seul le scan horaire l'aurait rattrapé | Surveiller le **répertoire** parent avec un filtre `restrict="^/etc/ssh/sshd_config$"`. Vérifié : deux remplacements successifs donnent deux alertes |
| 7 | Le port 2222 restait occupé d'une campagne à l'autre | `sshd` réécrit le nom de son processus (`sshd: /usr/sbin/sshd -p 2222 [listener]`) : le motif ancré du point 5 ne le trouvait jamais | Retrouver le processus **par son port** : `ss -lntpH 'sport = :2222'` |
| 8 | Juste après l'enrôlement d'un agent, quelques événements disparaissent | Tant que l'agent est « Pending », le manager n'a pas encore chargé sa clé | Attendre que l'agent soit « Active » (plus une minute) avant de lancer une campagne |
| 9 | Le script de campagne témoin attendait indéfiniment le redémarrage du manager | `wazuh-control status` renvoie le code 1 dès qu'un service optionnel est arrêté, et `cmd \| grep -q` échoue avec `set -o pipefail` (SIGPIPE) | Capturer la sortie dans une variable, ignorer le code de retour, tester le contenu |

**À retenir :**
- Une règle qui passe `wazuh-logtest` peut quand même échouer en conditions réelles (problèmes 3, 4 et 6). Seule une campagne de bout en bout avec vérité terrain le révèle.
- Le problème 6 n'apparaissait **pas** dans la première campagne : tout marchait sur un poste neuf. C'est la campagne témoin, lancée juste après, qui l'a révélé. **Une détection doit être testée plusieurs fois, pas une seule.**
- Pendant le débogage, j'ai redémarré le manager en pleine répétition. Plutôt que de publier des chiffres obtenus avec des coupures, j'ai rejoué les campagnes sur une installation propre.

## Limites connues

- **100104** se déclenchera aussi lors des mises à jour de paquets (`apt upgrade` dépose de nouveaux binaires). En production, il faudrait la corréler avec les journaux `dpkg` (règle 2902) pour ignorer les installations légitimes.
- **100106** signale toute modification de `sshd_config`. Avec `report_changes`, on pourrait n'alerter en niveau élevé que sur les directives sensibles (`PermitRootLogin yes`, `PasswordAuthentication yes`).
- **100113** ne couvre que les échecs passant par PAM. Une authentification par clé SSH refusée n'est pas comptée.
- Les tests sont menés sur **un seul poste Linux en conteneur**. Pas de Windows (voir [extension-windows.md](extension-windows.md)), pas de trafic réseau réel.
