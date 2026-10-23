package com.akeeper.ui;

import android.Manifest;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Apps installées demandant INTERNET ; requiert QUERY_ALL_PACKAGES (déclaré pour le pare-feu par app). */
final class AppCatalog {

    private AppCatalog() {
    }

    /** Appel coûteux (IPC + lecture des labels) : jamais sur le thread principal. */
    static List<AppEntry> load(PackageManager packageManager, String ownPackage) {
        List<PackageInfo> packages = packageManager.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS));
        var networked = packages.stream()
                .filter(info -> info.applicationInfo != null && !info.packageName.equals(ownPackage))
                .filter(info -> info.requestedPermissions != null
                        && Arrays.asList(info.requestedPermissions).contains(Manifest.permission.INTERNET))
                .toList();
        Map<Integer, Long> perUid = networked.stream()
                .collect(Collectors.groupingBy(info -> info.applicationInfo.uid, Collectors.counting()));
        Function<PackageInfo, AppEntry> toEntry = info -> {
            var app = info.applicationInfo;
            return new AppEntry(info.packageName, packageManager.getApplicationLabel(app).toString(), app.uid,
                    (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0, (int) (perUid.get(app.uid) - 1));
        };
        return networked.stream().map(toEntry).toList();
    }
}
