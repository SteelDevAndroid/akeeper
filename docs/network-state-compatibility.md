# aKeeper — État réseau et profils de compatibilité

## Network State Engine

Le service VPN maintient un état compact du meilleur réseau physique non-VPN : transport (Wi-Fi, Ethernet, cellulaire, autre), réseau facturé, itinérance, validation Internet et portail captif. Le suivi utilise `ConnectivityManager` sur un thread dédié puis repasse sur le thread principal du service pour toute décision qui modifie le VPN.

La première politique contextuelle concerne l'option « Ne pas filtrer le réseau local ». La préférence utilisateur reste nécessaire, mais elle n'est appliquée que si le réseau est :

- Wi-Fi ou Ethernet ;
- validé par Android ;
- hors portail captif ;
- hors itinérance ;
- hors Protection avancée Android.

Sur un réseau cellulaire, inconnu, non validé ou captif, le LAN reste dans le tunnel même si l'utilisateur a activé l'option. Comme les routes d'un `VpnService` sont immuables après `establish()`, une transition qui change la décision reconstruit le tunnel. L'état est conservé pendant cette reconstruction afin d'éviter une boucle de redémarrage.

Cette couche est volontairement indépendante du moteur Rust : elle décide de la configuration du tunnel, tandis que le dataplane continue à appliquer les règles DNS/SNI/IP et le pare-feu par UID.

## Profils de compatibilité applicatifs

`CompatibilityProfile` classe les apps réseau dans quatre profils :

| Profil | Détection | Comportement |
|---|---|---|
| `DEFAULT` | aucune règle particulière | comportement normal |
| `FINANCE` | catégorie Android `CATEGORY_FINANCE` | avertissement renforcé avant blocage |
| `PAYMENT` | paquet de paiement explicitement reconnu | avertissement renforcé avant blocage |
| `SYSTEM_CONNECTIVITY` | composants Android/Google nécessaires à la connectivité | avertissement renforcé avant blocage |

Les profils ne créent **aucune exclusion du VPN** et ne modifient pas silencieusement les règles de blocage. Une action explicite de l'utilisateur reste prioritaire : après l'avertissement, l'app peut être bloquée comme n'importe quelle autre app. Cette règle évite qu'un profil de compatibilité devienne un canal de contournement.

Les listes de paquets explicitement reconnues doivent rester courtes, documentées et testées. Les apps bancaires génériques ne sont pas détectées par nom de paquet : la catégorie Android Finance est utilisée quand l'éditeur l'a déclarée.

## Tests attendus

- Wi-Fi/Ethernet validé : le bypass LAN peut être appliqué si demandé.
- Cellulaire, roaming, portail captif, réseau non validé : bypass LAN refusé.
- Transition Wi-Fi validé → cellulaire : reconstruction du tunnel et suppression des routes exclues.
- App Finance/Paiement/Connectivité critique : avertissement avant blocage.
- Confirmation utilisateur après avertissement : la règle par UID est bien appliquée.
