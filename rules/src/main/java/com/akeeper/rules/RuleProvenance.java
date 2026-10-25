package com.akeeper.rules;

public record RuleProvenance(int category, String source, String license, String url,
                             long retrievedAt, long expiresAt, String sha256) {
    public boolean freshAt(long epochSeconds) {
        return expiresAt <= 0 || epochSeconds <= expiresAt;
    }
}
