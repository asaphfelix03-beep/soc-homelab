# FAQ technique

Les questions qu'on pose le plus souvent sur ce projet, avec des réponses courtes. Les détails sont dans le [rapport](rapport.md) et le [catalogue des règles](regles-detection.md).

## Architecture

**Pourquoi Wazuh plutôt que Splunk ou Elastic Security ?**
Wazuh est open source et gratuit, sans limite de volume. Il réunit dans un seul outil un agent (FIM, collecte de journaux, inventaire, audit CIS), un moteur de règles et un SIEM basé sur OpenSearch. Pour un lab, c'est la solution la plus complète sans licence. Les concepts (décodeurs, règles, niveaux, corrélation) se transposent à Splunk ou à Elastic.

**Pourquoi Docker et pas des machines virtuelles ?**
Pour la **reproductibilité** : n'importe qui peut relancer le lab avec trois commandes, et les campagnes donnent les mêmes résultats d'une exécution à l'autre. En contrepartie, un conteneur ne permet pas certains contrôles (partitions, pare-feu, `auditd`, paramètres du noyau). C'est documenté dans les limites.

**Comment les composants communiquent-ils ?**
L'agent envoie ses événements au manager sur le port 1514, en TCP chiffré. Le manager applique les décodeurs puis les règles, et transmet les alertes à l'indexer (OpenSearch) via Filebeat, en TLS. Le dashboard interroge l'indexer et l'API du manager. Tous les ports sont liés à `127.0.0.1`.

## Règles de détection

**Comment fonctionne une règle Wazuh ?**
Un événement passe d'abord par un **décodeur**, qui en extrait des champs (`srcuser`, `dstuser`, `file`…), puis par un **arbre de règles**. Une règle enfant (`if_sid`) n'est testée que si sa règle parente a correspondu. La règle la plus spécifique qui correspond produit l'alerte, avec son niveau (0 à 15).

**Qu'est-ce qu'une règle de corrélation ?**
Une règle qui tient compte d'événements **précédents**. La 100112 se déclenche sur un ajout au groupe `sudo` (100110), seulement si un compte a été créé (5902) dans les 10 minutes précédentes, sur la même machine. Deux événements banals isolés deviennent un incident de niveau 14.

**Pourquoi `if_matched_sid` et pas `if_matched_group` pour la règle 100113 ?**
Les tests avec `wazuh-logtest` ont montré qu'avec `if_matched_group`, la règle ne comptait pas les échecs PAM et ne se déclenchait jamais, même après 15 échecs. La règle 5503 (« PAM: User login failed ») couvre déjà sudo, su, login et SSH, donc `if_matched_sid` sur 5503 suffit.

**Pourquoi `same_user` et pas `same_field dstuser` ?**
`dstuser` est un champ **statique** extrait par le décodeur. `same_field` ne fonctionne qu'avec les champs dynamiques. Les champs statiques ont leurs propres options, comme `same_user`.

**Comment as-tu choisi les niveaux ?**
Par rapport au **seuil de triage de 7** : sous 7, l'alerte est enregistrée mais non traitée. Les actions de persistance (cron, service, clé SSH) sont au niveau 10, les élévations de privilèges (sudoers, binaire système) au niveau 12, les corrélations au niveau 13 ou 14. Les documents utilisateur descendent au niveau 3 (règle 100120) pour réduire le bruit.

**Comment évites-tu qu'une règle anti-bruit masque une vraie attaque ?**
La règle 100120 ne concerne que les fichiers *documents* (`.txt`, `.pdf`, `.docx`…) hors de tout dossier caché. `~/.ssh/authorized_keys`, `.bashrc` ou `.profile` restent signalés normalement, ce qui a été vérifié en conditions réelles. Les suppressions ne sont pas atténuées : une suppression massive peut indiquer une destruction de données.

## Méthode

**Comment sais-tu qu'une alerte correspond bien à un scénario ?**
Le script enregistre l'heure de début et de fin de chaque scénario (la vérité terrain). Une alerte appartient au scénario dont la fenêtre la contient, du début du scénario jusqu'au début du suivant. Une pause de 45 s sépare les scénarios pour éviter les chevauchements.

**À quoi sert la campagne témoin ?**
À mesurer l'apport **réel** des règles personnalisées. On rejoue exactement les mêmes scénarios avec les règles désactivées. La seule différence entre les deux campagnes est le fichier `local_rules.xml`.

**Pourquoi répéter la campagne plusieurs fois ?**
Une détection qui marche une fois peut échouer la suivante. C'est exactement ce qui s'est passé avec la surveillance FIM d'un fichier isolé (voir la question suivante). La répétition donne aussi une fourchette de temps de détection au lieu d'une seule valeur.

**Quel a été le bug le plus intéressant ?**
La surveillance temps réel d'un fichier isolé (`/etc/ssh/sshd_config`) fonctionnait au premier changement, puis plus jamais. `sed -i` ne modifie pas le fichier : il en écrit un nouveau et le renomme, avec un nouvel inode. La surveillance (inotify) suivait l'ancien inode. Correction : surveiller le **répertoire** `/etc/ssh` avec un filtre `restrict`.

**Pourquoi S10 met-il jusqu'à 2 minutes à être détecté ?**
Les ports ne sont pas surveillés en temps réel : l'agent exécute `ss -lntu` toutes les 120 s et compare avec le résultat précédent. Le temps de détection dépend donc du moment où tombe la prochaine exécution. Réduire la fréquence accélère la détection mais augmente la charge.

**Tes scénarios sont-ils de vraies attaques ?**
Non, et c'est volontaire. Ce sont des actions d'administration qui laissent **les mêmes traces** qu'une attaque : un compte créé, une tâche cron, une clé SSH ajoutée. On peut les rejouer sans risque et de façon identique, ce qui permet de les mesurer. Ils ne couvrent pas l'évasion d'un vrai attaquant (désactivation de l'agent, effacement des journaux, exécution en mémoire).

## Limites et suite

**Quelle est la principale limite ?**
Un seul poste Linux, sans Windows ni Active Directory, alors que c'est l'essentiel de ce que surveille un SOC. La suite logique est un poste Windows avec Sysmon : voir [extension-windows.md](extension-windows.md).

**Que ferais-tu en production ?**
- Corréler la règle 100104 avec `dpkg`, pour ignorer les binaires installés par une mise à jour légitime.
- Ajouter `auditd`, pour voir les commandes exécutées et pas seulement les fichiers modifiés.
- Envoyer les alertes de niveau 12 et plus vers une messagerie, et ajouter une réponse active (blocage du compte après la règle 100114).
- Mesurer le bruit sur plusieurs semaines d'activité réelle, et pas seulement sur quelques actions de référence.
