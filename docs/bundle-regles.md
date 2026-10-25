# Bundle de règles signé

Format retenu à la place du protobuf de la spec (§7), écart n°4 acté le 23 octobre 2026 : une enveloppe binaire de taille fixe qui transporte des FST déjà construits. Il n'y a ni dépendance protobuf côté Java, ni reconstruction des listes sur le téléphone.

Implémentations :
- `rust/crates/akeeper-proto/src/bundle.rs` : parseur borné (fuzzé, cible `bundle`) et construction du message à signer ;
- `rules/.../BundleVerifier.java` : vérification de l'enveloppe et de la signature dans l'app ;
- `rust/crates/akeeper-bundle` : outil du pipeline, qui construit, signe et vérifie.

Les deux côtés testent le même fichier, `rules/src/test/resources/com/akeeper/rules/fixture-v5.akrb`, signé avec une clé de test publique. Un changement de format casse donc les tests Rust et Java à la fois.

## Enveloppe

Entiers en gros-boutiste.

| Offset | Taille | Champ | Règle |
|---|---|---|---|
| 0 | 4 | magic | `AKRB` |
| 4 | 2 | format | `1` |
| 6 | 1 | key_id | `0` ou `1` : index de la clé publique embarquée |
| 7 | 1 | réservé | `0` |
| 8 | 8 | version | monotone, ≤ 2⁶³ − 1 |
| 16 | 8 | created_at | secondes Unix, sert au GET conditionnel |
| 24 | 4 | payload_len | |
| 28 | payload_len | payload | sections |
| fin − 64 | 64 | signature | Ed25519 (RFC 8032) de tous les octets qui précèdent |

- La taille du fichier doit valoir exactement `28 + payload_len + 64`, et ne pas dépasser 32 Mio.
- La signature couvre l'en-tête, `key_id` compris : on ne peut pas faire passer un bundle pour signé par l'autre clé.

## Sections

Chaque section commence par `kind u8, category u8, 0u16, len u32`, suivis de `len` octets. Les sections couvrent exactement le payload, avec 64 sections au plus.

| kind | Contenu | Utilisation |
|---|---|---|
| 1 `DOMAINS` | FST de domaines en labels inversés, au format de `Blocklist` ; somme de contrôle vérifiée au chargement | filtrage DNS et SNI |
| 2 `CIDRS` | plages de 17 octets : préfixe sur l'espace IPv6 (l'IPv4 est stockée en `::ffff:a.b.c.d`, préfixe + 96), puis l'adresse | IP des résolveurs DoH : RST sur TCP/443 |
| 3 `NOTICE` | texte UTF-8 : sources, licences, liens | écran « Licences » (R1) |

Catégories : 1 publicité et traqueurs, 2 malware, 3 hameçonnage, 4 DoH, 5 exclusions (liste blanche).
- Un type ou une catégorie inconnus sont ignorés, ce qui laisse un bundle plus récent fonctionner sur une ancienne app.
- Les exclusions (`DOMAINS`/5) ne bloquent rien : leurs noms, sous-domaines compris, échappent aux catégories, en plus de ceux compilés dans le moteur (`rules/sources/default-allow.txt`). Elles ne dépendent pas du choix des catégories, et ni la liste personnelle ni le contournement DNS ne sont rouverts.
- Une liste DoH (`DOMAINS`/4) présente dans le bundle remplace la liste provisoire embarquée dans le moteur.
- Toutes les catégories sont appliquées pour l'instant ; le choix par catégorie arrive avec l'écran R2.

## Activation dans l'app

1. `RuleUpdateWorker` (WorkManager, toutes les 12 h, réseau requis) télécharge `akeeper.rulesUrl`, avec `If-Modified-Since` = `created_at` du bundle actif.
2. `RuleStore.install` lit au plus 32 Mio, vérifie l'enveloppe et la signature, puis exige `version > max(plancher, version active)`.
3. Le bundle est écrit dans `noBackupFilesDir/rules/bundle.akrb.tmp` (fsync), puis renommé en `bundle.akrb` (`ATOMIC_MOVE`, fsync du répertoire).
4. Le plancher `rules/floor` est écrit de la même façon, **après** l'activation : une coupure entre les deux étapes laisse un bundle valide, de version ≥ plancher.
5. Le service est notifié et appelle `NativeEngine.setRules`, qui construit le filtre hors du thread moteur puis le remplace d'un bloc.

Au démarrage, `RuleStore.openActive` revérifie le fichier et cède au moteur le **même descripteur** : une activation concurrente remplace le fichier par `rename` sans toucher ce descripteur. Si le bundle est absent ou invalide, le moteur tourne avec la liste personnelle et le repli DoH embarqué. C'est aussi le cas d'un bundle authentique que le moteur ne sait pas charger : refuser de démarrer couperait la protection, et le plancher interdirait d'en revenir. Pour cette raison, `akeeper-bundle verify` charge aussi le bundle comme le moteur avant toute publication.

Plancher effectif : `max(akeeper.minRuleVersion embarqué dans l'APK, rules/floor)`. Il ne redescend jamais, même si le bundle est supprimé.

## Liste intégrée à l'APK

Sans bundle téléchargé valide, l'app donne au moteur `rules/src/main/assets/default-rules.akrb`, une liste HaGeZi LIGHT (70 390 domaines, catégorie publicité et traqueurs, licence GPL-3.0). Sans elle, une installation neuve ne filtrerait rien.
- **Pas de signature Ed25519** : le fichier porte 64 octets nuls et sa version vaut 0. Son authenticité est celle de l'APK qui le contient, et `verify` le refuse, donc il ne peut jamais passer pour une mise à jour. Un bundle téléchargé, lui, est toujours vérifié.
- **Priorité** : `RuleStore.openRules()` donne le bundle téléchargé s'il est valide, sinon la liste intégrée. Un téléchargement corrompu retombe donc sur elle.
- **Copie** : l'asset n'est lisible qu'en flux, alors que le moteur veut un descripteur. Il est recopié de façon atomique dans `noBackupFilesDir/rules/embedded.akrb` à chaque nouvelle version de l'app seulement.
- **Régénération** : `scripts/build-default-rules.sh` télécharge la liste (ou lit `LIGHT_LIST=<fichier>`) et appelle `akeeper-bundle build-unsigned`. Le texte `NOTICE` indique la source, la licence et la date, et alimente l'écran « Licences ».
- **Test** : `the_shipped_default_list_blocks_ad_domains_and_spares_common_sites` charge ce fichier et vérifie qu'il bloque des domaines publicitaires sans toucher aux sites courants.

## Clés

- Les deux clés publiques sont fournies par la propriété Gradle `akeeper.rulePublicKeys` (hex, séparées par une virgule), validée à la configuration puis injectée dans `BuildConfig`.
- Sans clé, aucun bundle n'est accepté.
- La graine privée se crée avec `akeeper-bundle keygen` sur la machine de signature, hors ligne ou en HSM (spec §3) ; elle ne va jamais dans le dépôt ni dans la CI de l'app.
- **Rotation** : signer avec la clé 1 pendant qu'une version de l'app embarque encore la clé 0, puis publier une version de l'app qui remplace la clé 0.

```bash
cd rust
cargo run -p akeeper-bundle -- keygen /chemin/hors-depot/cle0.seed     # affiche la clé publique
cargo run -p akeeper-bundle -- build --seed cle0.seed --key-id 0 --version 42 \
    --ads hagezi-light.txt --phishing phishing-army.txt --malware urlhaus.txt \
    --doh doh-hosts.txt --doh-ips doh-ips.txt --notice LICENCES.txt --out bundle.akrb
cargo run -p akeeper-bundle -- verify bundle.akrb <clé0 hex> <clé1 hex>
```

## Pipeline de publication

`scripts/build-rules.sh <dossier>` construit `bundle.akrb`, le signe et le **revérifie avec les clés publiques de l'app** avant de le laisser sortir. `.github/workflows/rules.yml` l'exécute toutes les 6 h et le publie sur GitHub Pages. Un job `preflight` valide désormais explicitement `RULES_SEED_B64`, `RULES_KEY_ID` et `RULES_PUBLIC_KEYS` avant toute construction : configuration absente, clé publique mal formée, identifiant de clé incohérent ou graine qui ne décode pas exactement 32 octets font échouer le workflow au lieu de le laisser silencieusement en état `skipped`.

| Catégorie | Source | Notes |
|---|---|---|
| Publicité et traqueurs | HaGeZi LIGHT | GPL-3.0 |
| Hameçonnage | Phishing Army | une liste de moins de 10 000 domaines est refusée |
| Malware | URLhaus (`recent.csv`, URL « online ») | hôtes seulement, sans adresse IP ; les hôtes sous un domaine du top 100 000 Tranco sont écartés ; **catégorie omise** sans `URLHAUS_AUTH_KEY` |
| Exclusions | `rules/sources/default-allow.txt`, plus la liste de la variable `ALLOW_LIST_URL` si elle est lisible | une liste blanche externe en panne n'empêche pas la publication ; sa source est ajoutée à la `NOTICE` via `ALLOW_LIST_NOTICE` |
| DoH | `rules/sources/doh-hosts.txt` et `doh-ips.txt` | fichiers versionnés, aussi compilés dans le moteur comme repli |

- **Garde-fous** : HaGeZi sous 30 000 domaines ou Phishing Army sous 10 000 font échouer le job, car une source tronquée ferait perdre la protection à tous les appareils. Une panne d'URLhaus ou de Tranco n'empêche pas la publication, elle retire seulement la catégorie malware.
- **Version** : l'heure Unix de la construction, donc monotone (anti-rollback).
- **Clé URLhaus** : elle fait partie de l'URL de téléchargement. Le script n'utilise pas `-v`, et `--fail` évite que curl n'affiche l'URL en cas d'erreur. Le point d'accès `urlhaus-api.abuse.ch/v2/files/exports/<clé>/recent.csv` vient de la documentation d'abuse.ch ; il n'a pas pu être essayé sans clé.
- **Mise à jour conditionnelle** : GitHub Pages date le fichier de son déploiement, postérieur au `created_at` du bundle. L'app reçoit donc un 200 à chaque passage, puis constate que la version est déjà connue. Cela coûte un téléchargement de 2,5 Mo toutes les 12 h par appareil.

### À faire par le porteur du projet
1. Générer la clé **hors ligne** : `cargo run -p akeeper-bundle -- keygen /chemin/hors-depot/cle0.seed`. La commande affiche la clé publique. Une seconde clé sert à la rotation.
2. Dans Settings › Secrets and variables › Actions :
   - secret `RULES_SEED_B64` : `base64 -w0 cle0.seed` ;
   - secret `URLHAUS_AUTH_KEY` (facultatif) ;
   - variable `RULES_PUBLIC_KEYS` : les clés publiques hex, séparées par une virgule ;
   - variables facultatives `ALLOW_LIST_URL` (liste blanche supplémentaire, un domaine par ligne) et `ALLOW_LIST_NOTICE` (source et licence affichées dans Licences) ;
   - variable `RULES_KEY_ID` : `0` ou `1`, la position de la clé qui signe.
3. Settings › Pages › Source : **GitHub Actions**, puis lancer le workflow `rules` à la main une première fois.
4. Dans `gradle.properties`, renseigner **les mêmes clés** (`akeeper.rulePublicKeys`) et `akeeper.rulesUrl=https://<compte>.github.io/<dépôt>/bundle.akrb`. Sans les clés, l'app n'accepte aucun bundle ; avec d'autres clés, elle les refuse tous.
5. Archiver l'accord d'abuse.ch avant d'activer la catégorie malware.

## Pas encore fait

- **Serveur** : le pipeline existe, mais il n'est pas activé tant que les étapes ci-dessus ne sont pas faites. Sans `akeeper.rulesUrl`, la mise à jour n'est pas planifiée.
- **Pinning TLS** du serveur (spec §5) : il viendra avec les vrais certificats. L'intégrité repose sur Ed25519, pas sur TLS.
- **Bundle embarqué** dans l'APK pour le premier démarrage : il faut d'abord la clé de production.
