
package ru.urfu.passwordcheck.generator;

import java.security.SecureRandom;
import java.util.Objects;

public final class SecurePasswordGenerator implements PasswordGenerator {

    private static final String LETTERS =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private static final String DIGITS = "0123456789";

    private static final String SYMBOLS = "!@#$%^&*";

    private final SecureRandom random = new SecureRandom();

    @Override
    public String generate(GenerationOptions options) {
        Objects.requireNonNull(options, "options");

        StringBuilder alphabet = new StringBuilder();

        if (options.letters()) {
            alphabet.append(LETTERS);
        }

        if (options.digits()) {
            alphabet.append(DIGITS);
        }

        if (options.symbols()) {
            alphabet.append(SYMBOLS);
        }

        String allowed = alphabet.toString();

        String password;

        do {
            StringBuilder result = new StringBuilder(options.length());

            for (int i = 0; i < options.length(); i++) {
                int index = random.nextInt(allowed.length());
                result.append(allowed.charAt(index));
            }

            password = result.toString();

        } while (
                (options.letters() && !containsAny(password, LETTERS)) ||
                        (options.digits() && !containsAny(password, DIGITS)) ||
                        (options.symbols() && !containsAny(password, SYMBOLS))
        );

        return password;
    }

    private static boolean containsAny(String text, String characters) {
        for (int i = 0; i < text.length(); i++) {
            if (characters.indexOf(text.charAt(i)) >= 0) {
                return true;
            }
        }

        return false;
    }
}
