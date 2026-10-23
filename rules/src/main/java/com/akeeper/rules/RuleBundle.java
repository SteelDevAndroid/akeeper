package com.akeeper.rules;

/**
 * En-tête vérifié d'un bundle de règles (format dans {@code docs/bundle-regles.md}).
 *
 * @param keyId     index de la clé publique embarquée qui a signé le bundle
 * @param version   monotone : un bundle n'est activé que si sa version dépasse celle déjà vue
 * @param createdAt secondes Unix, sert de date de référence pour la mise à jour conditionnelle
 */
public record RuleBundle(int keyId, long version, long createdAt) {
}
