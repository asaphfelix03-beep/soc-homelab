# Extension : ajouter un poste Windows (Sysmon + agent Wazuh)

> Cette extension n'a **pas** été exécutée dans la campagne publiée : elle demande une machine virtuelle Windows. C'est la prochaine étape du projet.

## Pourquoi

La plupart des postes d'entreprise sont sous Windows. Sysmon (Microsoft Sysinternals) journalise la création de processus, les connexions réseau et les modifications du registre. Wazuh possède déjà des règles pour ces événements.

## Étapes

1. **Créer une VM Windows 11** (image d'évaluation gratuite de Microsoft) dans VirtualBox ou Hyper-V, avec une carte réseau en mode « réseau privé hôte ».
2. **Ouvrir les ports d'enrôlement du manager** : dans `lab/docker-compose.yml`, ajoute dans le service `wazuh.manager` en remplaçant l'IP par celle de ton interface « réseau privé hôte » :

   ```yaml
       ports:
         - "192.168.56.1:1514:1514"
         - "192.168.56.1:1515:1515"
   ```

3. **Installer Sysmon** avec une configuration reconnue, par exemple [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config), dans PowerShell administrateur :

   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   ```

4. **Installer l'agent Wazuh 4.14.9** pour Windows (MSI officiel), avec `WAZUH_MANAGER="192.168.56.1"`.
5. **Collecter les journaux Sysmon** : ajoute dans `C:\Program Files (x86)\ossec-agent\ossec.conf` :

   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

   Puis redémarre le service : `Restart-Service WazuhSvc`.

## Scénarios Windows à ajouter (même principe : actions d'administration inoffensives)

| Technique | Action de test sur ta VM | Source de l'événement |
|---|---|---|
| T1136.001 | `net user test_lab /add` | Journal Sécurité, 4720 |
| T1098 | `net localgroup Administrateurs test_lab /add` | Journal Sécurité, 4732 |
| T1053.005 | `schtasks /create /tn MajLab /tr notepad.exe /sc daily` | Journal Sécurité, 4698 |
| T1547.001 | Ajout d'une valeur dans `HKCU\...\CurrentVersion\Run` | Sysmon, événement 13 |
| T1543.003 | `sc create ServiceLab binPath= C:\Windows\System32\notepad.exe` | Système, 7045 |

Ajoute ces lignes dans `tests/scenarios.csv` avec un script PowerShell équivalent à `run_scenarios.sh`. L'analyse (`analysis/analyze.py`) fonctionnera sans modification.
