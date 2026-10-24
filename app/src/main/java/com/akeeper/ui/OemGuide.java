package com.akeeper.ui;

import java.util.Locale;
import java.util.Optional;

/** Constructeurs dont la gestion agressive de la batterie arrête les services en arrière-plan (spec §8.5). */
enum OemGuide {
    XIAOMI, SAMSUNG, OPPO, VIVO, HONOR;

    /** Marques regroupées sous un même constructeur (Redmi et POCO chez Xiaomi, OnePlus et realme chez Oppo…). */
    static Optional<OemGuide> of(String manufacturer) {
        var name = manufacturer == null ? "" : manufacturer.toLowerCase(Locale.ROOT);
        return switch (name) {
            case "xiaomi", "redmi", "poco" -> Optional.of(XIAOMI);
            case "samsung" -> Optional.of(SAMSUNG);
            case "oppo", "oneplus", "realme" -> Optional.of(OPPO);
            case "vivo", "iqoo" -> Optional.of(VIVO);
            case "honor" -> Optional.of(HONOR);
            default -> Optional.empty();
        };
    }
}
