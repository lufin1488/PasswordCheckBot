
package ru.urfu.passwordcheck.generator;

public record GenerationOptions(
        int length,
        boolean letters,
        boolean digits,
        boolean symbols
) {

    public GenerationOptions {

        if (length < 8 || length > 128) {
            throw new IllegalArgumentException(
                    "Длина пароля должна быть от 8 до 128"
            );
        }

        if (!letters && !digits && !symbols) {
            throw new IllegalArgumentException(
                    "Выберите хотя бы один набор символов"
            );
        }
    }
}
