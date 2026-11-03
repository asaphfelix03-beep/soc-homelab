# Brouillon de post LinkedIn

> À publier avec la capture `docs/img/dashboard.png` (ou une courte vidéo du dashboard). Ajoute le lien du dépôt en premier commentaire : LinkedIn diffuse moins les posts qui contiennent un lien.

---

🛡️ J'ai monté un mini-SOC chez moi, et je l'ai mesuré au lieu de seulement l'installer.

La question : sur un poste Linux, un SIEM détecte-t-il vraiment les techniques d'attaque courantes ?

Ce que j'ai fait :
🔹 Déployé Wazuh 4.14.9 (manager, indexer, dashboard) en Docker, avec un poste Ubuntu surveillé
🔹 Écrit 11 règles de détection reliées à MITRE ATT&CK, dont des corrélations (« compte créé puis promu admin en moins de 10 min », « connexion réussie juste après une série d'échecs »)
🔹 Rejoué 10 techniques (cron, clé SSH, sudoers, service systemd…) avec une vérité terrain horodatée
🔹 Rejoué exactement la même campagne SANS mes règles, pour mesurer leur apport réel (test A/B)
🔹 Analysé les alertes en Python/pandas et publié un dashboard

📊 Résultats :
✅ 10/10 techniques détectées au-dessus du seuil de triage, contre 5/10 avec les règles natives seules
✅ La bonne technique MITRE sur 10/10 alertes, contre 2/10
✅ 0 faux positif de mes règles pendant l'activité normale
✅ Score CIS du poste : 48 % → 62 % après durcissement

💡 Ce que j'ai appris : tout marchait au premier essai… sur un poste neuf. C'est le 2ᵉ passage qui a révélé que la surveillance temps réel d'un fichier disparaît quand `sed -i` le remplace. J'ai documenté 9 problèmes de ce type et leurs corrections. Une détection se valide en la testant plusieurs fois.

Prochaine étape : un poste Windows avec Sysmon.

Je cherche un stage de 3 mois en cybersécurité ou en analyse de données à partir de fin février 2027. Vos retours m'intéressent !

#cybersécurité #SOC #Wazuh #BlueTeam #MITREATTACK #SIEM #Python #CôteDIvoire

---

**Premier commentaire :** 🔗 Code, rapport et dashboard : https://github.com/asaphfelix03-beep/soc-homelab
