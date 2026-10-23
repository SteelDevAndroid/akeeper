# aKeeper — Évaluation des listes de blocage

Évaluation des sources proposées pour les catégories de l'écran R2 (`docs/ui-ecrans.md` §5). Fichiers téléchargés et mesurés le 23 octobre 2026, conditions d'usage lues à la source.

## 1. Verdict

| Fonction | Source | Priorité | Verdict |
|---|---|---|---|
| Publicité et traqueurs | HaGeZi Multi LIGHT (défaut), NORMAL (option « renforcé ») | P0 | **Retenue** |
| Blocage généraliste | StevenBlack Unified Hosts | Comparaison | **Écartée** : licence non commerciale d'une sous-source, sémantique « hôte exact » |
| Malware | URLhaus (abuse.ch) | P0 | **Bloquée** : autorisation écrite d'abuse.ch / Spamhaus requise avant toute intégration |
| Hameçonnage | Phishing Army | P1 | **Retenue sous réserve** de la revue des conditions des 9 sources amont |

**Profil par défaut décidé : HaGeZi LIGHT + Phishing Army** (2,4 Mo de FST, 225 235 domaines). NORMAL reste une option « renforcé ».

Le P0 « malware » n'a donc pas encore de source utilisable. HaGeZi NORMAL déclare couvrir aussi malware et hameçonnage : c'est le palliatif tant qu'URLhaus n'est pas autorisé, sans équivalence garantie.

## 2. Mesures

Les domaines sont normalisés en minuscules et dédoublonnés. Le recouvrement se mesure avec la sémantique du moteur : une entrée bloque aussi ses sous-domaines.

| Liste | Domaines | Texte | FST | Construction FST* |
|---|---|---|---|---|
| HaGeZi LIGHT | 70 378 | 1,5 Mo | 777 Ko | 0,20 s |
| HaGeZi NORMAL | 172 593 | 3,5 Mo | 1,9 Mo | 0,60 s |
| StevenBlack | 71 493 | 1,5 Mo | — | — |
| Phishing Army | 155 395 | 3,4 Mo | — | — |
| LIGHT + Phishing Army | 225 235 | 4,9 Mo | 2,4 Mo | 0,71 s |

\* Sur une machine x86 de CI, à multiplier par plusieurs sur un téléphone. La recherche reste sous 1 µs par nom de domaine.

| Recouvrement | Part déjà couverte |
|---|---|
| StevenBlack ⊂ HaGeZi LIGHT | 20,8 % |
| StevenBlack ⊂ HaGeZi NORMAL | 27,4 % |
| Phishing Army ⊂ HaGeZi LIGHT | 0,6 % |
| Phishing Army ⊂ HaGeZi NORMAL | 0,7 % |

Phishing Army apporte presque uniquement des domaines nouveaux. StevenBlack couvre surtout un autre périmètre (hôtes publicitaires et adware historiques) que HaGeZi.

## 3. Détail par source

### HaGeZi Multi (P0, retenue)

- **Licence** : GPL-3.0, la même qu'aKeeper. On peut l'intégrer à un bundle redistribué, avec attribution.
- **Format** : `wildcard/*-onlydomains.txt`. Chaque entrée bloque aussi tous ses sous-domaines (les sous-domaines redondants sont retirés de la liste), soit exactement la sémantique de `Blocklist::blocks`.
- **LIGHT** : publicités, traqueurs, métriques et télémétrie, construit uniquement à partir de domaines des classements Top 1M/10M. L'auteur le présente comme sans restriction notable, d'où le choix par défaut.
- **NORMAL** : ajoute hameçonnage, malware, arnaques et cryptojacking, avec plus de risque de faux positifs. C'est l'option « renforcé ».
- **Fraîcheur** : en-tête `Expires: 8 hours`.
- **Limite** : HaGeZi ne sépare pas publicité et traqueurs. R2 affichera donc une seule catégorie « Publicités et traqueurs ».

### StevenBlack Unified Hosts (comparaison, écartée)

- **Licence** : MIT pour le projet, mais le fichier agrège des sources sous leurs propres licences. Le bloc MVPS (winhelp2002) est en **CC BY-NC-SA 4.0** : pas d'usage commercial et partage à l'identique obligatoire. AdAway (CC BY 3.0) et KADhosts (CC BY-SA 4.0) exigent une attribution. Le bloc someonewhocares.org n'a pas été vérifié.
- **Sémantique** : c'est un fichier hosts, où chaque entrée vise un hôte exact. Avec la règle « sous-domaines inclus » du moteur, chaque entrée bloquerait plus large que prévu, d'où plus de faux positifs.
- **Apport** : seuls 21 à 27 % de ses domaines sont déjà couverts par HaGeZi. Il apporterait donc environ 52 000 à 56 000 domaines, mais la licence suffit à l'écarter d'un bundle redistribué.

### URLhaus (P0, bloquée)

- **Accès** : le fichier hosts public (`/downloads/hostfile/`) répond **HTTP 410**. Tout export demande désormais une Auth-Key nominative.
- **Conditions d'abuse.ch** (version du 21 octobre 2026) :
  - usage gratuit réservé aux fins non lucratives, dans les limites de volume ;
  - usage commercial ou à but lucratif soumis à un abonnement géré par Spamhaus ;
  - interdiction de créer des œuvres dérivées des plateformes sans accord exprès.
- **Conséquence** : rediffuser les domaines d'URLhaus dans un bundle signé envoyé à chaque appareil exige un **accord écrit**, même pour une app gratuite. Embarquer la clé d'API dans l'app est exclu.
- **Action** : demander l'autorisation à abuse.ch / Spamhaus en décrivant l'usage (agrégation côté serveur, rediffusion en bundle signé, volume d'appareils).

### Phishing Army (P1, sous réserve)

- **Conditions propres** : aucune restriction sur ses flux générés, y compris pour un usage commercial. Le travail d'agrégation est libre, le code du générateur est en GPL-3.0.
- **Conditions amont** : Phishing Army précise qu'il ne cède aucun droit sur les données de ses 9 sources : PhishTank (Cisco Talos), OpenPhish, CERT.PL, Phishunt, urlscan.io, PhishStats, StalkPhish, URLAbuse (CC BY 4.0, attribution obligatoire) et AntiPhish.org. Il faut vérifier chacune avant de diffuser.
- **Format** : un domaine par ligne. Les hébergeurs mutualisés ne sont pas bloqués en bloc, seuls les noms d'hôte locataires le sont : la sémantique « sous-domaines inclus » reste sûre.
- **Fraîcheur** : en-tête `Expires: 4 hours`, et les domaines d'hameçonnage vivent peu. Il faut mettre à jour le bundle au moins toutes les 12 heures, sans quoi la catégorie perd l'essentiel de son intérêt.
- **Domaines de test** : `amiprotected.it` et `www.amiprotected.it` sont volontairement inclus pour tester le filtrage. Ce sont des pages inoffensives, à garder.

## 4. Conséquences sur la conception

1. **Construire le FST côté serveur.** La construction prend de 0,2 à 0,7 s en CI, donc nettement plus sur un téléphone, et la liste texte est 2 à 4 fois plus grosse que le FST. Le bundle signé (J5) transporte donc des FST déjà construits, un par catégorie, que le moteur charge sans les reconstruire. Le fichier texte de J1 reste réservé à la liste personnelle, qui est courte.
2. **Un FST par catégorie** : `ads_trackers` (HaGeZi LIGHT ou NORMAL), `phishing` (Phishing Army) et `malware` (URLhaus, quand l'accord existe). Les interrupteurs de R2 activent ou désactivent un FST sans rien reconstruire.
3. **Ordre d'évaluation** : exceptions personnelles, puis domaines bloqués personnels, puis catégories actives. Une exception gagne toujours.
4. **Écran R2** : remplacer « Publicités » + « Traqueurs » par « Publicités et traqueurs ». Retirer « Contenus adultes » tant qu'aucune source n'est choisie, ajouter « Hameçonnage ». Proposer LIGHT ou NORMAL (« standard » / « renforcé »).
5. **Attribution** : l'écran « Licences » (R1) liste chaque source, sa licence et son lien. Le bundle porte ces métadonnées pour que l'écran suive les sources effectivement incluses.
6. **Fraîcheur** : le pipeline serveur respecte l'en-tête `Expires` de chaque source et n'interroge jamais plus souvent qu'elle ne le demande.

## 5. Actions

| # | Action | Responsable |
|---|---|---|
| 1 | Demande d'autorisation écrite pour URLhaus (abuse.ch / Spamhaus) | Porteur du projet |
| 2 | Revue des conditions des 9 sources de Phishing Army (redistribution, attribution) — **acceptée**, à mener avant la première diffusion | Porteur du projet |
| 3 | Profil par défaut — **décidé : LIGHT + Phishing Army** | Porteur du projet |
| 4 | Pipeline serveur : téléchargement, normalisation, FST par catégorie, signature Ed25519 (J5) | Développement |
| 5 | Mettre à jour R2 et R1 selon §4 | Développement |

## Sources consultées

- [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) et en-têtes de `wildcard/light-onlydomains.txt` et `wildcard/multi-onlydomains.txt`
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) et en-têtes de sources du fichier `hosts`
- [URLhaus Community API](https://urlhaus.abuse.ch/api/) et [conditions d'utilisation d'abuse.ch](https://abuse.ch/terms-of-use/)
- [Phishing Army, usage et licence](https://phishing.army/license/) et [SOURCES.md](https://github.com/drego85/PhishingArmyCore/blob/master/SOURCES.md)
