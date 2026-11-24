package ru.urfu.passwordcheck.strength;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RuleBasedStrengthEvaluatorTest {

    private final StrengthEvaluator evaluator =
            new RuleBasedStrengthEvaluator(
                    new PasswordDictionary(
                            Set.of("password", "admin", "qwerty", "iloveyou")
                    )
            );

    @Test
    void shortPasswordIsWeak() {
        StrengthResult result = evaluator.evaluate("aB7!kQ2");

        assertEquals(StrengthLevel.WEAK, result.level());
        assertTrue(result.reasons().contains(
                "Пароль слишком короткий"
        ));
    }

    @Test
    void longPasswordWithOneCategoryIsMedium() {
        StrengthResult result =
                evaluator.evaluate("mzkvprtxhwnjqfyds");

        assertEquals(StrengthLevel.MEDIUM, result.level());
        assertTrue(result.reasons().contains(
                "Низкое разнообразие символов"
        ));
    }

    @Test
    void dominantDictionaryWordMakesPasswordWeak() {
        StrengthResult result =
                evaluator.evaluate("Password7!kR2@Lm");

        assertEquals(StrengthLevel.WEAK, result.level());
        assertTrue(result.reasons().contains(
                "Пароль содержит распространённые слова"
        ));
    }

    @Test
    void shortDictionaryWordLimitsPasswordToMedium() {
        StrengthResult result =
                evaluator.evaluate("xT7#adminQ9!kR8p");

        assertEquals(StrengthLevel.MEDIUM, result.level());
        assertTrue(result.reasons().contains(
                "Пароль содержит распространённые слова"
        ));
    }

    @Test
    void detectsLeetSubstitutions() {
        StrengthResult result = evaluator.evaluate("P@ssw0rd");

        assertEquals(StrengthLevel.WEAK, result.level());
        assertTrue(result.reasons().contains(
                "Обнаружено словарное слово с типовыми подстановками"
        ));
    }

    @Test
    void detectsAscendingSequence() {
        StrengthResult result =
                evaluator.evaluate("X!123456789kR2@z");

        assertEquals(StrengthLevel.WEAK, result.level());
        assertTrue(result.reasons().contains(
                "Обнаружена последовательность букв или цифр"
        ));
    }

    @Test
    void detectsDescendingSequence() {
        StrengthResult result =
                evaluator.evaluate("X!987654321kR2@z");

        assertEquals(StrengthLevel.WEAK, result.level());
        assertTrue(result.reasons().contains(
                "Обнаружена последовательность букв или цифр"
        ));
    }

    @Test
    void detectsMultipleWeaknesses() {
        StrengthResult result =
                evaluator.evaluate("passwordabcdefghij");

        assertEquals(StrengthLevel.WEAK, result.level());

        assertTrue(result.reasons().contains(
                "Низкое разнообразие символов"
        ));

        assertTrue(result.reasons().contains(
                "Пароль содержит распространённые слова"
        ));

        assertTrue(result.reasons().contains(
                "Обнаружена последовательность букв или цифр"
        ));
    }

    @Test
    void passwordWithoutDetectedWeaknessesIsStrong() {
        StrengthResult result =
                evaluator.evaluate("xT7#mQ9!vL2@kR8p");

        assertEquals(StrengthLevel.STRONG, result.level());
    }





    @Test
    void rejectsNullPassword() {
        assertThrows(
                NullPointerException.class,
                () -> evaluator.evaluate(null)
        );
    }

    @Test
    void rejectsEmptyPassword() {
        assertThrows(
                IllegalArgumentException.class,
                () -> evaluator.evaluate("")
        );
    }
}