# aKeeper — Dossier de publication Google Play

État au 26 octobre 2026, vérifié sur les pages d'aide Play citées en fin de document. Les textes destinés à la Play Console sont en anglais, langue de la revue ; à adapter si la fiche est d'abord publiée en français.

## 1. Liste de contrôle

| # | Élément | Où | État |
|---|---|---|---|
| 1 | AAB signé avec la clé d'importation (Play App Signing) | CI `ci.yml` (`bundleRelease`, secrets `RELEASE_*`) | À faire : créer la clé d'importation et les secrets |
| 2 | `targetSdk` 36, `.so` alignées 16 KB | `build-logic`, `scripts/check-16kb.sh` | Fait |
| 3 | R8 (code + ressources), `mapping.txt` archivé par la CI | `app/build.gradle.kts`, `app/proguard-rules.pro` | Fait ; importer `mapping.txt` avec chaque version |
| 4 | Divulgation in-app avec consentement explicite avant `VpnService.prepare()` | Écran O1, bouton **Accepter et continuer** | Fait |
| 5 | Formulaire **VpnService** | App content › VPN service | À remplir (§2) |
| 6 | Déclaration **QUERY_ALL_PACKAGES** | App content › Sensitive permissions | À remplir (§4) |
| 7 | Déclaration de service de premier plan **systemExempted** + vidéo | App content › Foreground service permissions | À remplir (§3) |
| 8 | **Data safety** | App content › Data safety | À remplir (§5) |
| 9 | Politique de confidentialité (URL publique) | `docs/play/confidentialite.html`, publiée par `rules.yml` sur Pages | Compléter l'éditeur et le contact, puis publier |
| 10 | Fiche Play mentionnant l'usage de `VpnService` | Main store listing | À rédiger (§6) |
| 11 | Classification du contenu, public cible, publicités | App content | Questionnaire : aucune publicité, public 18+ ou tous publics hors enfants |
| 12 | Tests fermés (comptes personnels créés après nov. 2023 : 12 testeurs pendant 14 jours avant la production) | Testing › Closed testing | À planifier |

## 2. Formulaire VpnService

La politique admet les VPN dont c'est la **fonctionnalité principale**, et cite la sécurité de l'appareil et les outils réseau. aKeeper entre dans ce cas : le VPN local est le moteur du pare-feu et du filtre DNS.

**Point de vigilance — chiffrement.** La politique demande de « chiffrer les données de l'appareil jusqu'à l'extrémité du tunnel ». Ici, l'extrémité du tunnel est **sur l'appareil** : aucun octet ne quitte le téléphone par le tunnel. Le trafic des apps sort ensuite tel qu'elles l'émettent (TLS compris), sans déchiffrement ni MITM. Les pare-feu locaux du même type sont publiés sur Play, mais il faut le dire explicitement au relecteur (texte ci-dessous).

Texte proposé :

> **Core functionality.** aKeeper is an on-device firewall and DNS filter. VpnService is its core functionality: the app creates a local tunnel so that its on-device engine can (1) answer DNS queries and refuse ad, tracker, phishing and malware domains, (2) let the user block Internet access per app, and (3) prevent apps from bypassing the filter (encrypted DNS, QUIC). There is no remote VPN server: the tunnel endpoint is the app itself, on the device. No traffic is sent to the developer or any third party, and no traffic content is decrypted or inspected beyond the DNS question and the TLS server name.
>
> **Encryption.** The tunnel never leaves the device, so no user data travels in clear text between the device and a VPN endpoint. Connections are relayed to their original destination exactly as the apps produced them, end-to-end encryption included.
>
> **User data.** Domain names, the originating app and per-app traffic volumes are kept only on the device, encrypted (SQLCipher), for at most 7 days, and can be disabled or cleared. A prominent in-app disclosure with an explicit "Accept and continue" button is shown before the VPN permission is requested.
>
> **No monetization of traffic.** The app shows no ads, does not redirect, reroute or alter traffic for monetization, and contains no analytics SDK.

## 3. Service de premier plan `systemExempted`

Android réserve ce type à quelques cas, dont « VPN apps (configured using Settings > Network & Internet > VPN) » : c'est le cas d'aKeeper une fois le consentement `prepare()` accordé. Aucun type `vpn` n'existe. La Play Console demande une déclaration par type : description, impact d'une interruption, cas d'usage et **vidéo de démonstration**.

> **Description.** The foreground service is the VpnService that runs aKeeper's on-device firewall. It must run as long as protection is on, because it owns the VPN interface: if Android stopped it, apps would either lose connectivity (always-on VPN with lockdown) or reach the Internet unfiltered.
>
> **User impact if deferred or interrupted.** Immediate loss of protection: ads, trackers and malicious domains are no longer blocked, and per-app Internet blocking stops.
>
> **User control.** The service starts only after the user grants the system VPN consent. A persistent notification shows the status with a Pause action, and the user can turn the VPN off at any time in Android settings.

Vidéo (30 à 60 s, appareil réel) : onboarding O1 → consentement système → accueil « Protégé » → notification permanente → blocage d'une app dans l'onglet Apps → déconnexion depuis Réglages › Réseau › VPN.

## 4. `QUERY_ALL_PACKAGES`

Les usages cités par la politique sont la recherche sur l'appareil, les antivirus, les gestionnaires de fichiers et les navigateurs. Les pare-feu par app ne sont **ni cités ni exclus** : c'est le **risque principal** du dossier (R-02 de la spec).

> **Why broad visibility is required.** aKeeper's core feature is a per-app firewall: the user decides which installed apps may access the Internet. Any app with the INTERNET permission can open network connections, including apps without a launcher activity (background services, system components, widgets, keyboards). A narrower `<queries>` declaration would hide those apps, which would leave unlisted apps that the user cannot block, defeating the firewall. The list is read on the device to display the Apps screen; it is never stored (only the package names the user chooses to block are kept, encrypted), never transmitted and never used for ads or analytics.

**Repli si la déclaration est refusée** : retirer la permission et déclarer `<queries><intent><action android:name="android.intent.action.MAIN" /><category android:name="android.intent.category.LAUNCHER" /></intent></queries>`. Le pare-feu ne couvre alors que les apps avec icône ; l'écran Apps doit le dire. Le moteur, qui bloque par UID, n'est pas touché.

## 5. Data safety

Selon Play, une donnée traitée **uniquement sur l'appareil** n'est pas une collecte (« collection » = transmission hors de l'appareil). aKeeper n'envoie rien : réponses proposées.

| Question | Réponse |
|---|---|
| Does your app collect or share any of the required user data types? | **No** |
| Is all of the user data collected by your app encrypted in transit? | Sans objet (aucune collecte) |
| Do you provide a way for users to request that their data is deleted? | Sans objet ; le journal local s'efface dans les Réglages |

Écart avec la spec (§9, « historique de navigation déclaré dès qu'un journal de domaines existe, même local ») : la règle Play actuelle exclut explicitement le traitement local. Déclarer une collecte qui n'a pas lieu serait inexact. La spec est mise à jour en conséquence. Si une télémétrie ou un envoi de rapport de plantage est ajouté, ce formulaire doit être revu **avant** sa publication.

## 6. Fiche Play

La politique exige que l'usage de `VpnService` figure dans la fiche. Description courte (80 caractères) :

> Pare-feu et filtre DNS local : bloquez pubs, traqueurs et apps, sans serveur.

Paragraphe à inclure dans la description longue :

> aKeeper utilise l'API VpnService d'Android pour créer un VPN **local** : le trafic de vos apps est filtré sur votre téléphone, sans passer par un serveur. aKeeper ne déchiffre pas vos connexions et n'envoie aucune donnée, ni à nous ni à des tiers. Les domaines consultés sont conservés au plus 7 jours, chiffrés, sur l'appareil, et vous pouvez désactiver ce journal.

Captures : O1 (divulgation), accueil Protégé, écran Apps, Activité, Listes de blocage, tuile Réglages rapides.

## 7. Points ouverts

- **Politique de confidentialité** : renseigner l'éditeur et l'adresse de contact dans `docs/play/confidentialite.html`. Elle est publiée à `https://<compte>.github.io/<dépôt>/confidentialite.html` par le workflow `rules`, donc seulement une fois les secrets de règles configurés.
- **Tests fermés** : s'ils sont exigés pour le compte développeur, compter 14 jours avant la mise en production.
- **Validation sur appareil** avant envoi : la vidéo FGS et les captures supposent une build release minifiée testée, R8 compris.

## Sources

- [Politique VpnService](https://support.google.com/googleplay/android-developer/answer/12564964)
- [Visibilité des paquets (`QUERY_ALL_PACKAGES`)](https://support.google.com/googleplay/android-developer/answer/10158779)
- [Section Data safety](https://support.google.com/googleplay/android-developer/answer/10787469)
- [Types de services de premier plan](https://developer.android.com/develop/background-work/services/fgs/service-types)
- [Exigences de services de premier plan sur Play](https://support.google.com/googleplay/android-developer/answer/13392821)
