package com.akeeper.ui;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class OemGuideTest {

    @ParameterizedTest
    @CsvSource({"Xiaomi,XIAOMI", "Redmi,XIAOMI", "POCO,XIAOMI", "samsung,SAMSUNG", "OnePlus,OPPO", "OPPO,OPPO",
            "realme,OPPO", "vivo,VIVO", "iQOO,VIVO", "HONOR,HONOR"})
    void groupsBrandsUnderTheirManufacturer(String manufacturer, OemGuide expected) {
        assertThat(OemGuide.of(manufacturer)).contains(expected);
    }

    @ParameterizedTest
    @CsvSource({"Google", "Motorola", "Fairphone", "''"})
    void ignoresOtherManufacturers(String manufacturer) {
        assertThat(OemGuide.of(manufacturer)).isEmpty();
    }

    @Test
    void toleratesAMissingManufacturer() {
        assertThat(OemGuide.of(null)).isEmpty();
    }
}
