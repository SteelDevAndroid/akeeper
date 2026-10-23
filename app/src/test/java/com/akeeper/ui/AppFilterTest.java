package com.akeeper.ui;

import com.akeeper.ui.AppFilter.Scope;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AppFilterTest {

    private static final AppEntry BROWSER = new AppEntry("org.example.browser", "Navigateur", 10001, false, 0);
    private static final AppEntry SOCIAL = new AppEntry("com.example.social", "Réseau social", 10002, false, 0);
    private static final AppEntry GAME = new AppEntry("com.example.puzzle", "Énigmes", 10003, false, 0);
    private static final AppEntry PLAY = new AppEntry("com.google.android.gms", "Services Google Play", 10004, true, 2);
    private static final List<AppEntry> APPS = List.of(BROWSER, SOCIAL, GAME, PLAY);

    @Test
    void allHidesSystemAppsAndListsBlockedFirstThenByFrenchCollation() {
        var result = AppFilter.apply(APPS, "", Scope.ALL, Set.of(SOCIAL.packageName()));

        assertThat(result).containsExactly(SOCIAL, GAME, BROWSER);
    }

    @Test
    void scopesSelectBlockedOrSystemApps() {
        assertThat(AppFilter.apply(APPS, "", Scope.BLOCKED, Set.of(PLAY.packageName()))).containsExactly(PLAY);
        assertThat(AppFilter.apply(APPS, "", Scope.SYSTEM, Set.of())).containsExactly(PLAY);
    }

    @Test
    void searchMatchesLabelCaseInsensitivelyOrPackageName() {
        assertThat(AppFilter.apply(APPS, "  RÉSEAU ", Scope.ALL, Set.of())).containsExactly(SOCIAL);
        assertThat(AppFilter.apply(APPS, "puzzle", Scope.ALL, Set.of())).containsExactly(GAME);
    }
}
