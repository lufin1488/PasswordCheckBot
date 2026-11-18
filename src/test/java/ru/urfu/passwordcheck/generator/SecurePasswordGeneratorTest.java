
package ru.urfu.passwordcheck.generator;

import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SecurePasswordGeneratorTest {

    private final PasswordGenerator generator =
            new SecurePasswordGenerator();

    @Test
    void generatesCorrectLength() {
        GenerationOptions options =
                new GenerationOptions(16, true, true, true);

        String password = generator.generate(options);

        assertEquals(16, password.length());
    }

    @Test
    void generatesOnlyDigits() {
        GenerationOptions options =
                new GenerationOptions(12, false, true, false);

        String password = generator.generate(options);

        assertTrue(password.matches("[0-9]{12}"));
    }

    @Test
    void generatesOnlyLetters() {
        GenerationOptions options =
                new GenerationOptions(12, true, false, false);

        String password = generator.generate(options);

        assertTrue(password.matches("[a-zA-Z]{12}"));
    }

    @RepeatedTest(10)
    void includesAllSelectedGroups() {
        GenerationOptions options =
                new GenerationOptions(20, true, true, true);

        String password = generator.generate(options);

        assertTrue(password.matches(".*[a-zA-Z].*"));
        assertTrue(password.matches(".*[0-9].*"));
        assertTrue(password.matches(".*[!@#$%^&*].*"));
    }

    @Test
    void rejectsNullOptions() {
        assertThrows(
                NullPointerException.class,
                () -> generator.generate(null)
        );
    }
}
