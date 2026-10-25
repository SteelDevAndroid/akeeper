# Sécurité CI et chaîne d'approvisionnement

Ce document décrit les contrôles ajoutés pour les propositions 15 et 20 de l'audit aKeeper.

## Contrôles CI

Le workflow `.github/workflows/security.yml` complète la CI fonctionnelle :

- **OSV-Scanner PR** sur `rust/Cargo.lock`, bloquant l'introduction de nouvelles vulnérabilités Rust connues sans dépendre du Dependency graph GitHub. Le nouveau `verification-metadata.xml` n'est volontairement pas utilisé comme base PR lors de son premier ajout : il ferait apparaître comme « nouvelles » les dépendances Gradle/AGP déjà présentes ;
- **cargo-audit** sur le workspace Rust, avec échec sur advisory ou warning ;
- **cargo-deny** pour interdire les dépendances yanked, les versions wildcard et les sources Git/registry non approuvées ;
- **CodeQL** sur Java/Kotlin (build manuel Gradle) et Rust ;
- **MobSFScan** sur les sources Android, avec rapport SARIF ;
- **APK statique** : `lint`, vérification `apksigner` de l'APK debug et rapport APKLeaks ;
- **SBOM CycloneDX JSON** produit avec Syft/Anchore et conservé comme artifact de workflow ;
- **Gradle Dependency Verification** : `gradle/verification-metadata.xml` fixe les SHA-256 des artefacts Maven/Gradle résolus.

Le workflow tourne également sur `main` et chaque lundi. Les contrôles de sécurité sont séparés du workflow `ci` pour que leur état soit visible indépendamment des builds Android/Rust. Les uploads CodeQL/SARIF sont désactivés sur les PR de fork, dont le `GITHUB_TOKEN` n'a pas le droit `security-events:write`; les analyses réelles s'exécutent sur `main` et les branches internes.

## Politique Rust / FFI

Les invariants suivants sont obligatoires :

- aucun `unsafe` hors de `akeeper-ffi` ;
- `unwrap`, `expect`, indexation non contrôlée et `panic!` interdits par les lints du workspace hors tests ;
- toute entrée JNI qui exécute du code Rust susceptible de paniquer est confinée par `catch_unwind` ;
- les descripteurs cédés au natif sont toujours fermés, y compris sur erreur ;
- les entrées volumineuses sont bornées **avant allocation**.

Bornes runtime principales :

| Ressource | Limite |
|---|---:|
| Bundle signé | 32 MiB |
| Liste personnelle | 64 MiB |
| Règles UID reçues depuis Java | 16 384 UID |
| Requêtes DNS amont en attente | 1 024 |
| Flux UDP NAT | 1 024 |
| Flux TCP | 512 |
| Événements en mémoire | 4 096 |
| Taille inspectée d'un ClientHello TLS | `tls::MAX_RECORD` |

Les dépassements sont refusés ou dégradés proprement ; ils ne doivent pas déclencher d'allocation non bornée ni traverser JNI sous forme de panic.

## Validation attendue

Pour une PR qui touche le moteur natif ou les dépendances :

```bash
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
cargo deny --all-features check
```

Le fuzzing planifié reste la validation principale des parseurs `packet`, `dns`, `transport`, `tls` et `bundle`.
