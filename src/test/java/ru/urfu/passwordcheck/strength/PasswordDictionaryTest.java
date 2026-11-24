package ru.urfu.passwordcheck.strength;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PasswordDictionaryTest {

    @Test
    void loadsDictionaryFromResource() {
        PasswordDictionary dictionary =
                PasswordDictionary.fromResource(
                        "/dictionaries/common-passwords.txt"
                );

        assertTrue(dictionary.contains("password"));
        assertTrue(dictionary.contains("PASSWORD"));
        assertTrue(dictionary.contains("qwerty"));
    }

    @Test
    void rejectsMissingResource() {
        assertThrows(
                IllegalArgumentException.class,
                () -> PasswordDictionary.fromResource(
                        "/missing-dictionary.txt"
                )
        );
    }

    @Test
    void evaluatesWithRealDictionary() {
        PasswordDictionary dictionary =
                PasswordDictionary.fromResource(
                        "/dictionaries/common-passwords.txt"
                );

        StrengthEvaluator evaluator =
                new RuleBasedStrengthEvaluator(dictionary);

        StrengthResult result = evaluator.evaluate("Password");

        assertEquals(StrengthLevel.WEAK, result.level());

        assertTrue(result.reasons().contains(
                "Пароль входит в словарь распространённых паролей"
        ));
    }
}