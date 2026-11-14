package ru.urfu.passwordcheck.generator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GenerationOptionsTest {

    @Test
    void createsValidOptions() {
        GenerationOptions options =
                new GenerationOptions(16, true, true, false);

        assertEquals(16, options.length());
        assertTrue(options.letters());
        assertTrue(options.digits());
        assertFalse(options.symbols());
    }

    @Test
    void rejectsInvalidLength() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new GenerationOptions(5, true, true, true)
        );
    }

    @Test
    void rejectsEmptyCharacterSets() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new GenerationOptions(16, false, false, false)
        );
    }
}
