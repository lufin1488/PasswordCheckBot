
package ru.urfu.passwordcheck.command.impl;

import ru.urfu.passwordcheck.command.Command;
import ru.urfu.passwordcheck.command.Request;
import ru.urfu.passwordcheck.command.Response;
import ru.urfu.passwordcheck.generator.GenerationOptions;
import ru.urfu.passwordcheck.generator.PasswordGenerator;

import java.util.List;
import java.util.Objects;

public final class GenCommand implements Command {

    private static final int DEFAULT_LENGTH = 16;

    private final PasswordGenerator generator;

    public GenCommand(PasswordGenerator generator) {
        this.generator = Objects.requireNonNull(generator);
    }

    @Override
    public String name() {
        return "gen";
    }

    @Override
    public String description() {
        return "Генерация случайного пароля";
    }

    @Override
    public String usage() {
        return "/gen [длина] [--letters] [--digits] [--symbols]";
    }

    @Override
    public String help() {
        return """
                Генерация безопасного пароля.
                Длина: от 8 до 128 символов.

                Примеры:
                /gen
                /gen 16
                /gen 20 --letters --digits
                /gen 12 --symbols

                Если типы символов не указаны,
                используются буквы, цифры и спецсимволы.
                """;
    }

    @Override
    public Response execute(Request request) {
        final GenerationOptions options;

        try {
            options = parseOptions(request.args());
        } catch (IllegalArgumentException exception) {
            return new Response(
                    "Ошибка: " + exception.getMessage()
                            + "\nИспользование: " + usage()
                            + "\nПодробнее: /help gen"
            );
        }

        try {
            String password = generator.generate(options);
            return new Response(
                    "Сгенерированный пароль:\n" + password
            );
        } catch (RuntimeException exception) {
            return new Response(
                    "Не удалось сгенерировать пароль. "
                            + "Попробуйте ещё раз."
            );
        }
    }

    private GenerationOptions parseOptions(List<String> args) {
        int length = DEFAULT_LENGTH;

        boolean letters = false;
        boolean digits = false;
        boolean symbols = false;

        boolean selected = false;
        boolean lengthSpecified = false;

        for (String arg : args) {
            switch (arg) {

                case "--letters" -> {
                    if (letters) {
                        throw new IllegalArgumentException(
                                "Параметр --letters указан повторно"
                        );
                    }
                    letters = true;
                    selected = true;
                }

                case "--digits" -> {
                    if (digits) {
                        throw new IllegalArgumentException(
                                "Параметр --digits указан повторно"
                        );
                    }
                    digits = true;
                    selected = true;
                }

                case "--symbols" -> {
                    if (symbols) {
                        throw new IllegalArgumentException(
                                "Параметр --symbols указан повторно"
                        );
                    }
                    symbols = true;
                    selected = true;
                }

                default -> {
                    if (arg.matches("-?[0-9]+")) {
                        if (lengthSpecified) {
                            throw new IllegalArgumentException(
                                    "Длина указана несколько раз"
                            );
                        }

                        try {
                            length = Integer.parseInt(arg);
                        } catch (NumberFormatException exception) {
                            throw new IllegalArgumentException(
                                    "Некорректная длина пароля"
                            );
                        }

                        lengthSpecified = true;
                    } else {
                        throw new IllegalArgumentException(
                                "Неизвестный аргумент: " + arg
                        );
                    }
                }
            }
        }

        if (!selected) {
            letters = true;
            digits = true;
            symbols = true;
        }

        return new GenerationOptions(
                length, letters, digits, symbols
        );
    }
}
