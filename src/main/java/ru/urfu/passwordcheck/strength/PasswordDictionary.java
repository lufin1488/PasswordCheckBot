package ru.urfu.passwordcheck.strength;

import java.nio.file.NoSuchFileException;
import java.util.Set;
import java.util.HashSet;
import java.util.Locale;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

public class PasswordDictionary {

    private final Set<String> dictionary;

    public PasswordDictionary(Set<String> words) {
        Set<String> normalized = new HashSet<>();

        for (String word : words) {
            normalized.add(word.toLowerCase(Locale.ROOT));
        }

        this.dictionary = Set.copyOf(normalized);
    }

    public boolean contains(String password) {
        return dictionary.contains(password.toLowerCase(Locale.ROOT));
    }


    public static PasswordDictionary fromResource(String path) {
        Set<String> words = new HashSet<>();

        try (InputStream stream =
                     PasswordDictionary.class.getResourceAsStream(path)) {

            if (stream == null) {
                throw new IllegalArgumentException(
                        "Словарь не найден: " + path
                );
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(stream, StandardCharsets.UTF_8))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    if (!line.isEmpty()) {
                        words.add(line);
                    }
                }
            }

        } catch (IOException e) {
            throw new UncheckedIOException("Ошибка чтения словаря", e);
        }

        return new PasswordDictionary(words);
    }
    public int matchedCharacters(String password) {
        String text = password.toLowerCase(Locale.ROOT);
        boolean[] covered = new boolean[text.length()];

        for (String word : dictionary) {
            if (word.length() < 4) {
                continue;
            }

            int index = text.indexOf(word);

            while (index != -1) {
                for (int i = index; i < index + word.length(); i++) {
                    covered[i] = true;
                }

                index = text.indexOf(word, index + 1);
            }
        }

        int count = 0;

        for (boolean value : covered) {
            if (value) {
                count++;
            }
        }

        return count;
    }

}