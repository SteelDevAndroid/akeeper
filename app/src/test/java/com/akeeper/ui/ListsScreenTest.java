package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.akeeper.R;
import com.akeeper.vpn.UserLists;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.util.function.BooleanSupplier;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class ListsScreenTest {

    private MainActivity activity;
    private ListsScreen screen;
    private View root;

    private void open() {
        activity = Robolectric.buildActivity(MainActivity.class).setup().get();
        activity.setContentView(R.layout.screen_lists);
        root = activity.findViewById(R.id.root);
        screen = new ListsScreen(activity, root, () -> {
        });
    }

    private void awaitUi(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            shadowOf(Looper.getMainLooper()).idle();
            assertThat(System.nanoTime()).as("condition atteinte à temps").isLessThan(deadline);
            Thread.sleep(10);
        }
    }

    @Test
    public void validatesTheDomainWhileTyping() {
        open();
        ViewGroup blocked = root.findViewById(R.id.lists_blocked);
        TextInputEditText field = blocked.findViewById(R.id.domain_input);
        TextInputLayout layout = blocked.findViewById(R.id.domain_input_layout);
        MaterialButton add = blocked.findViewById(R.id.domain_add);

        assertThat(add.isEnabled()).isFalse();
        field.setText("pas un domaine");
        assertThat(layout.getError()).isNotNull();
        assertThat(add.isEnabled()).isFalse();

        field.setText("Ads.Example.NET");
        assertThat(layout.getError()).isNull();
        assertThat(add.isEnabled()).isTrue();

        field.setText("");
        assertThat(layout.getError()).as("un champ vide n'est pas une erreur").isNull();
        assertThat(add.isEnabled()).isFalse();
        screen.close();
    }

    @Test
    public void addsAnExceptionThenRemovesItFromTheList() throws Exception {
        open();
        ViewGroup allowed = root.findViewById(R.id.lists_allowed);
        TextInputEditText field = allowed.findViewById(R.id.domain_input);
        field.setText("ok.example.org");
        ((MaterialButton) allowed.findViewById(R.id.domain_add)).performClick();

        var lists = UserLists.get(activity);
        awaitUi(() -> lists.lists().allowed().contains("ok.example.org"));
        awaitUi(() -> field.getText().length() == 0);
        assertThat(lists.lists().blocked()).doesNotContain("ok.example.org");
        awaitUi(() -> hasRowFor(allowed, "ok.example.org"));

        allowed.findViewById(R.id.domain_remove).performClick();
        awaitUi(() -> !lists.lists().allowed().contains("ok.example.org"));
        screen.close();
    }

    @Test
    public void showsTheDnsBypassWithoutASwitchAndGreysOutAbsentCategories() throws Exception {
        open();
        ViewGroup categories = root.findViewById(R.id.lists_categories);
        // Trois catégories et le contournement DNS ; ce dernier n'a pas d'interrupteur.
        assertThat(categories.getChildCount()).isEqualTo(4);
        assertThat(categories.getChildAt(3).findViewById(R.id.row_switch).getVisibility()).isEqualTo(View.GONE);
        // Aucun bundle téléchargé dans ce test : la liste intégrée ne porte que la publicité, pas encore les autres.
        awaitUi(() -> !categories.getChildAt(1).findViewById(R.id.row_switch).isEnabled()
                && categories.getChildAt(1).findViewById(R.id.row_subtitle) != null
                && ((TextView) categories.getChildAt(1).findViewById(R.id.row_subtitle)).getText().toString()
                .contains("Pas encore disponible"));
        screen.close();
    }

    private static boolean hasRowFor(ViewGroup box, String domain) {
        for (int i = 0; i < box.getChildCount(); i++) {
            var child = box.getChildAt(i);
            if (child instanceof ViewGroup group) {
                for (int j = 0; j < group.getChildCount(); j++) {
                    if (group.getChildAt(j).findViewById(R.id.domain_name) instanceof TextView name
                            && name.getText().toString().equals(domain)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
