package com.akeeper.ui;

import android.content.Context;
import android.content.pm.PackageManager;

import com.akeeper.R;
import com.akeeper.engine.FlowEvent;
import com.akeeper.vpn.RuleCategory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.HashMap;
import java.util.Map;

/** Libellés du journal : app d'un UID, raison d'un verdict, heure. Les UID sont résolus une fois par écran. */
final class EventText {

    private static final DateTimeFormatter TIME =
            DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT).withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter DATE_TIME =
            DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withZone(ZoneId.systemDefault());

    private final Context context;
    private final PackageManager packageManager;
    private final Map<Integer, String> labels = new HashMap<>();

    EventText(Context context) {
        this.context = context;
        this.packageManager = context.getPackageManager();
    }

    /** Nom de la première app de l'UID, suivi du nombre des autres si l'UID est partagé. */
    String app(int uid) {
        return labels.computeIfAbsent(uid, this::resolve);
    }

    private String resolve(int uid) {
        var packages = uid < 0 ? null : packageManager.getPackagesForUid(uid);
        if (packages == null || packages.length == 0) {
            return context.getString(R.string.unknown_app);
        }
        try {
            var label = packageManager.getApplicationInfo(packages[0], 0).loadLabel(packageManager).toString();
            return packages.length > 1 ? label + " +" + (packages.length - 1) : label;
        } catch (PackageManager.NameNotFoundException uninstalled) {
            return packages[0];
        }
    }

    String verdict(FlowEvent event) {
        return context.getString(event.blocked() ? R.string.verdict_blocked : R.string.verdict_allowed);
    }

    String reason(FlowEvent event) {
        return switch (event.reason()) {
            case NONE -> context.getString(R.string.reason_none);
            case PERSONAL -> context.getString(R.string.reason_personal);
            case EVASION -> context.getString(R.string.reason_evasion);
            case APP_FIREWALL -> context.getString(R.string.reason_app);
            case CATEGORY -> category(event.categoryId());
        };
    }

    private String category(int id) {
        for (var category : RuleCategory.values()) {
            if (category.id == id) {
                int name = switch (category) {
                    case ADS -> R.string.category_ads;
                    case MALWARE -> R.string.category_malware;
                    case PHISHING -> R.string.category_phishing;
                };
                return context.getString(R.string.reason_list, context.getString(name));
            }
        }
        return context.getString(R.string.reason_list_unknown);
    }

    /** Titre d'un groupe : « 14 h », précédé du jour s'il n'est pas aujourd'hui. */
    static String hour(long hourStartMillis) {
        var start = Instant.ofEpochMilli(hourStartMillis).atZone(ZoneId.systemDefault());
        var sameDay = start.toLocalDate().equals(java.time.LocalDate.now());
        return DateTimeFormatter.ofPattern(sameDay ? "HH 'h'" : "EEE d MMM · HH 'h'").format(start);
    }

    static String time(long millis) {
        return TIME.format(Instant.ofEpochMilli(millis));
    }

    static String dateTime(long millis) {
        return DATE_TIME.format(Instant.ofEpochMilli(millis));
    }
}
