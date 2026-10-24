package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;

class UserListsTest {

    @TempDir
    File dir;

    @Test
    void persistsBlocksAndExceptionsInTheFileTheEngineReads() throws Exception {
        var file = new File(dir, "blocklist.txt");
        var lists = new UserLists(file);

        assertThat(lists.add(UserLists.Kind.BLOCKED, " Ads.Example.NET ")).contains("ads.example.net");
        assertThat(lists.add(UserLists.Kind.ALLOWED, "*.ok.example")).contains("ok.example");

        assertThat(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8))
                .contains("\nads.example.net\n")
                .contains("\n@@ok.example\n");
        var reloaded = new UserLists(file).lists();
        assertThat(reloaded.blocked()).containsExactly("ads.example.net");
        assertThat(reloaded.allowed()).containsExactly("ok.example");
        assertThat(new File(dir, "blocklist.txt.tmp")).doesNotExist();
    }

    @Test
    void aDomainCannotBeBlockedAndAllowedAtOnce() throws Exception {
        var lists = new UserLists(new File(dir, "blocklist.txt"));
        lists.add(UserLists.Kind.BLOCKED, "x.example");

        lists.add(UserLists.Kind.ALLOWED, "x.example");

        assertThat(lists.lists().blocked()).isEmpty();
        assertThat(lists.lists().allowed()).containsExactly("x.example");
    }

    @Test
    void rejectsInvalidDomainsWithoutWriting() throws Exception {
        var file = new File(dir, "blocklist.txt");
        var lists = new UserLists(file);

        assertThat(lists.add(UserLists.Kind.BLOCKED, "not a domain")).isEmpty();

        assertThat(file).doesNotExist();
        assertThat(lists.lists()).isEqualTo(UserLists.Lists.EMPTY);
    }

    @Test
    void removesAndNotifiesObserversOnEachChangeOnly() throws Exception {
        var lists = new UserLists(new File(dir, "blocklist.txt"));
        var seen = new ArrayList<UserLists.Lists>();
        try (var ignored = lists.observe(seen::add)) {
            lists.add(UserLists.Kind.BLOCKED, "a.example");
            lists.add(UserLists.Kind.BLOCKED, "a.example");
            lists.remove(UserLists.Kind.BLOCKED, "a.example");
            lists.remove(UserLists.Kind.BLOCKED, "a.example");
        }
        assertThat(seen).hasSize(2);
        assertThat(lists.lists().blocked()).isEmpty();
    }

    @Test
    void readsAHandWrittenFileAndDropsInvalidLines() throws Exception {
        var file = new File(dir, "blocklist.txt");
        Files.write(file.toPath(),
                "# mes règles\nAds.Example.net  # pub\n@@ok.example\nnot valid\n@@\n\n".getBytes(StandardCharsets.UTF_8));

        var lists = new UserLists(file).lists();

        assertThat(lists.blocked()).containsExactly("ads.example.net");
        assertThat(lists.allowed()).containsExactly("ok.example");
    }
}
