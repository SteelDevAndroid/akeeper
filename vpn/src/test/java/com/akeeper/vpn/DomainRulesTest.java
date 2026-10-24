package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class DomainRulesTest {

    @ParameterizedTest
    @CsvSource({
            "ads.example.net,ads.example.net",
            "  Ads.Example.NET.  ,ads.example.net",
            "*.tracker.example,tracker.example",
            "xn--bcher-kva.example,xn--bcher-kva.example",
            "my_host.example.org,my_host.example.org",
    })
    void normalizesValidDomains(String input, String expected) {
        assertThat(DomainRules.normalize(input)).contains(expected);
    }

    @Test
    void convertsInternationalNamesToAscii() {
        assertThat(DomainRules.normalize("bücher.example")).contains("xn--bcher-kva.example");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "localhost", "example", "a*.example.com", "ads.*.example.com", "https://example.com",
            "example.com/path", "example.com:8080", "user@example.com", "bad domain.com", "-bad.example.com",
            "bad-.example.com", "a..example.com", "1.2.3.4", "10.0.0.0.8", "ex!ample.com", ".example.com"})
    void rejectsInvalidInput(String input) {
        assertThat(DomainRules.normalize(input)).isEmpty();
    }

    @Test
    void rejectsOverlongNamesAndLabels() {
        assertThat(DomainRules.normalize("a".repeat(64) + ".example")).isEmpty();
        assertThat(DomainRules.normalize("a".repeat(63) + ".example")).isPresent();
        assertThat(DomainRules.normalize(("a".repeat(60) + ".").repeat(5) + "com")).isEmpty();
        assertThat(DomainRules.normalize(null)).isEmpty();
    }
}
