package com.akeeper.ui;

import com.akeeper.vpn.LockdownStatus;

/** Ordre de l'onboarding (docs/ui-ecrans.md §3), déduit de l'état du système plutôt que mémorisé. */
final class OnboardingFlow {

    enum Step { DISCLOSURE, VPN_CONSENT, NOTIFICATIONS, LOCKDOWN, HOME }

    record Facts(boolean onboardingDone,
                 boolean disclosureAccepted,
                 boolean vpnConsent,
                 boolean notificationsGranted,
                 boolean notificationsAsked,
                 LockdownStatus lockdown) {
    }

    private OnboardingFlow() {
    }

    static Step next(Facts facts) {
        // Une fois l'onboarding terminé, l'accueil porte seul les écarts (révocation, verrouillage coupé).
        if (facts.onboardingDone()) {
            return Step.HOME;
        }
        if (!facts.vpnConsent()) {
            // La divulgation précède toujours prepare() : exigence de la politique Play VpnService.
            return facts.disclosureAccepted() ? Step.VPN_CONSENT : Step.DISCLOSURE;
        }
        if (!facts.notificationsGranted() && !facts.notificationsAsked()) {
            return Step.NOTIFICATIONS;
        }
        return facts.lockdown().failClosed() ? Step.HOME : Step.LOCKDOWN;
    }
}
