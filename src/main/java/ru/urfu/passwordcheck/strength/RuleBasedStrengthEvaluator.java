
package ru.urfu.passwordcheck.strength;

import java.util.List;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.time.LocalDate;
import java.time.DateTimeException;

public final class RuleBasedStrengthEvaluator
        implements StrengthEvaluator {

    private final PasswordDictionary dictionary;

    private static final List<String> KEYBOARD_ROWS = List.of(
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "йцукенгшщзхъ",
            "фывапролджэ",
            "ячсмитьбю"
    );

    private static final Pattern DATE_PATTERN = Pattern.compile(
            "(?<![0-9])([0-9]{2})([./-]?)([0-9]{2})\\2((?:19|20)[0-9]{2})(?![0-9])"
    );

    public RuleBasedStrengthEvaluator(
            PasswordDictionary dictionary
    ) {
        this.dictionary = Objects.requireNonNull(dictionary);
    }

    @Override
    public StrengthResult evaluate(String password) {

        Objects.requireNonNull(password, "Пароль не должен быть null");

        if (password.isEmpty()) {
            throw new IllegalArgumentException(
                    "Пароль должен содержать символы"
            );
        }

        List<String> reasons = new ArrayList<>();

        int length = password.length();
        StrengthLevel result;

        // 1.Проверка длины
        if (length < 8) {
            result = StrengthLevel.WEAK;
            reasons.add("Пароль слишком короткий");
        } else if (length < 16) {
            result = StrengthLevel.MEDIUM;
            reasons.add("Длина пароля средненькая");
        } else {
            result = StrengthLevel.STRONG;
            reasons.add("Длина приличная");
        }

        // 2.Проверка состава
        int categoryCount = countCategories(password);

        if (categoryCount <= 1) {
            result = length < 16
                    ? StrengthLevel.WEAK
                    : limitToMedium(result);

            reasons.add("Низкое разнообразие символов");

        } else if (categoryCount == 2) {
            result = limitToMedium(result);
            reasons.add("Используются только две категории символов");
        }

        // 3.Проверка словаря и подстановок
        String normalized = normalizeLeet(password, 'i');
        String alternative = normalizeLeet(password, 'l');

        if (dictionary.contains(password)) {

            result = StrengthLevel.WEAK;
            reasons.add("Пароль входит в словарь распространённых паролей");

        } else if (dictionary.contains(normalized)
                || dictionary.contains(alternative)) {

            result = StrengthLevel.WEAK;
            reasons.add("Обнаружено словарное слово с типовыми подстановками");

        } else {

            int directMatches = dictionary.matchedCharacters(password);

            int normalizedMatches = Math.max(
                    dictionary.matchedCharacters(normalized),
                    dictionary.matchedCharacters(alternative)
            );

            int matches = Math.max(
                    directMatches, normalizedMatches
            );

            if (matches > 0) {

                if (matches * 2 >= length) {
                    result = StrengthLevel.WEAK;
                } else {
                    result = limitToMedium(result);
                }

                reasons.add("Пароль содержит распространённые слова");

                if (normalizedMatches > directMatches) {
                    reasons.add("Обнаружены типовые подстановки символов");
                }
            }
        }

        // 4. Проверка повторений

        if (isRepeatedPassword(password)) {
            result = StrengthLevel.WEAK;
            reasons.add("Пароль состоит из повторяющихся групп символов");

        } else if (hasRepeatedCharacters(password)) {
            result = limitToMedium(result);
            reasons.add("Обнаружено повторение одинаковых символов");
        }

        // 5. Проверка последовательностей

        int sequenceLength = longestSequence(password);

        if (sequenceLength >= 4) {

            if (sequenceLength * 2 >= length) {
                result = StrengthLevel.WEAK;
            } else {
                result = limitToMedium(result);
            }

            reasons.add("Обнаружена последовательность букв или цифр");
        }

        // 6. Клавиатурные комбинации

        if (hasKeyboardPattern(password)) {
            result = limitToMedium(result);
            reasons.add("Обнаружена клавиатурная последовательность");
        }

        // 7. Проверка дат

        if (hasDate(password)) {
            result = length <= 10
                    ? StrengthLevel.WEAK
                    : limitToMedium(result);

            reasons.add("Пароль содержит дату");
        }

        return new StrengthResult(result, reasons);
    }

    private static int countCategories(String password) {

        boolean hasLowercase = false;
        boolean hasUppercase = false;
        boolean hasDigits = false;
        boolean hasSymbols = false;

        for (char c : password.toCharArray()) {

            if (Character.isLowerCase(c)) {
                hasLowercase = true;
            }

            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            }

            if (Character.isDigit(c)) {
                hasDigits = true;
            }

            if (!Character.isLetterOrDigit(c)) {
                hasSymbols = true;
            }
        }

        return (hasLowercase ? 1 : 0)
                + (hasUppercase ? 1 : 0)
                + (hasDigits ? 1 : 0)
                + (hasSymbols ? 1 : 0);
    }

    private static StrengthLevel limitToMedium(
            StrengthLevel level
    ) {
        return level == StrengthLevel.STRONG
                ? StrengthLevel.MEDIUM
                : level;
    }

    private static String normalizeLeet(
            String password, char oneReplacement
    ) {
        return password.toLowerCase(Locale.ROOT)
                .replace('@', 'a')
                .replace('4', 'a')
                .replace('0', 'o')
                .replace('3', 'e')
                .replace('$', 's')
                .replace('5', 's')
                .replace('7', 't')
                .replace('1', oneReplacement);
    }

    private static boolean isRepeatedPassword(String password) {

        String text = password.toLowerCase(Locale.ROOT);
        int length = text.length();

        for (int size = 1; size <= length / 2; size++) {

            if (length % size != 0) {
                continue;
            }

            boolean repeated = true;

            for (int i = size; i < length; i++) {
                if (text.charAt(i) != text.charAt(i % size)) {
                    repeated = false;
                    break;
                }
            }

            if (repeated) {
                return true;
            }
        }

        return false;
    }

    private static boolean hasRepeatedCharacters(String password) {

        int count = 1;

        for (int i = 1; i < password.length(); i++) {

            if (password.charAt(i) == password.charAt(i - 1)) {
                count++;

                if (count >= 4) {
                    return true;
                }

            } else {
                count = 1;
            }
        }

        return false;
    }

    private static int longestSequence(String password) {

        String text = password.toLowerCase(Locale.ROOT);

        int ascending = 1;
        int descending = 1;
        int longest = 1;

        for (int i = 1; i < text.length(); i++) {

            char previous = text.charAt(i - 1);
            char current = text.charAt(i);

            boolean sameGroup =
                    (previous >= 'a' && previous <= 'z'
                            && current >= 'a' && current <= 'z')
                            ||
                            (previous >= '0' && previous <= '9'
                                    && current >= '0' && current <= '9');

            if (sameGroup && current - previous == 1) {
                ascending++;
            } else {
                ascending = 1;
            }

            if (sameGroup && previous - current == 1) {
                descending++;
            } else {
                descending = 1;
            }

            longest = Math.max(
                    longest,
                    Math.max(ascending, descending)
            );
        }

        return longest;
    }

    private static boolean hasKeyboardPattern(String password) {

        String text = password.toLowerCase(Locale.ROOT);

        for (String row : KEYBOARD_ROWS) {

            String reversed = new StringBuilder(row)
                    .reverse()
                    .toString();

            for (int i = 0; i <= text.length() - 4; i++) {

                String part = text.substring(i, i + 4);

                if (row.contains(part) || reversed.contains(part)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean hasDate(String password) {

        Matcher matcher = DATE_PATTERN.matcher(password);

        while (matcher.find()) {

            int day = Integer.parseInt(matcher.group(1));
            int month = Integer.parseInt(matcher.group(3));
            int year = Integer.parseInt(matcher.group(4));

            try {
                LocalDate.of(year, month, day);
                return true;

            } catch (DateTimeException e) {
                // Совпадение не является корректной датой.
            }
        }

        return false;
    }
}
