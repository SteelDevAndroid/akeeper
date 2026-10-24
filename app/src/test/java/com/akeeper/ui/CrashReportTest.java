package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import android.content.Context;
import android.widget.TextView;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowDialog;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class CrashReportTest {

    private final Thread.UncaughtExceptionHandler original = Thread.getDefaultUncaughtExceptionHandler();
    private Context context;

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        // Le gestionnaire précédent est remplacé : l'appeler réellement ferait échouer le test.
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
        });
    }

    @After
    public void tearDown() {
        Thread.setDefaultUncaughtExceptionHandler(original);
    }

    @Test
    public void recordsAnUncaughtExceptionAndForgetsItOnceAcknowledged() {
        CrashReport.install(context);

        Thread.getDefaultUncaughtExceptionHandler()
                .uncaughtException(Thread.currentThread(), new IllegalStateException("boom du service"));

        var report = CrashReport.pending(context).orElseThrow();
        assertThat(report.text()).contains("IllegalStateException").contains("boom du service");
        CrashReport.acknowledge(context, report);
        assertThat(CrashReport.pending(context)).isEmpty();
    }

    @Test
    public void reportsNothingAfterACleanRun() {
        assertThat(CrashReport.pending(context)).isEmpty();
    }

    @Test
    public void showsThePreviousCrashAtLaunch() {
        CrashReport.install(context);
        Thread.getDefaultUncaughtExceptionHandler()
                .uncaughtException(Thread.currentThread(), new IllegalStateException("plantage précédent"));

        Robolectric.buildActivity(MainActivity.class).setup();

        var dialog = ShadowDialog.getLatestDialog();
        assertThat(dialog).isNotNull();
        TextView message = dialog.findViewById(android.R.id.message);
        assertThat(message.getText().toString()).contains("plantage précédent");
    }
}
