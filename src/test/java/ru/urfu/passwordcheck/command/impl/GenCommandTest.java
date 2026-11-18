
package ru.urfu.passwordcheck.command.impl;

import org.junit.jupiter.api.Test;
import ru.urfu.passwordcheck.command.Request;
import ru.urfu.passwordcheck.command.Response;
import ru.urfu.passwordcheck.generator.GenerationOptions;
import ru.urfu.passwordcheck.generator.PasswordGenerator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class GenCommandTest {

    private static class FakeGenerator implements PasswordGenerator {
        GenerationOptions received;

        @Override
        public String generate(GenerationOptions options) {
            received = options;
            return "test-password";
        }
    }

    private static Response execute(
            GenCommand command, String... args
    ) {
        return command.execute(
                new Request(1L, "gen", List.of(args))
        );
    }

    @Test
    void defaultOptions() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command);

        assertEquals(
                new GenerationOptions(16, true, true, true),
                fake.received
        );
        assertTrue(response.text().contains("test-password"));
    }

    @Test
    void customLengthAndCategories() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        execute(command, "20", "--letters", "--digits");

        assertEquals(
                new GenerationOptions(20, true, true, false),
                fake.received
        );
    }

    @Test
    void symbolsOnly() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        execute(command, "12", "--symbols");

        assertEquals(
                new GenerationOptions(12, false, false, true),
                fake.received
        );
    }

    @Test
    void invalidLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "5");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void unknownArgument() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "--unknown");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void duplicateLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "12", "20");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void helpAndMetadata() {
        GenCommand command = new GenCommand(options -> "test");

        assertEquals("gen", command.name());
        assertTrue(command.usage().contains("/gen"));
        assertTrue(command.help().contains("--symbols"));
    }

    @Test
    void minimumLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "8");

        assertEquals(8, fake.received.length());
        assertTrue(response.text().contains("test-password"));
    }

    @Test
    void maximumLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        execute(command, "128");

        assertEquals(128, fake.received.length());
    }

    @Test
    void lengthBelowMinimum() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "7");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void lengthAboveMaximum() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "129");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void nonNumericLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "abc");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void hugeLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(
                command, "999999999999999999999999"
        );

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

    @Test
    void digitsOnly() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        execute(command, "16", "--digits");

        assertEquals(
                new GenerationOptions(16, false, true, false),
                fake.received
        );
    }

    @Test
    void lettersOnly() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        execute(command, "16", "--letters");

        assertEquals(
                new GenerationOptions(16, true, false, false),
                fake.received
        );
    }

    @Test
    void negativeLength() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(command, "-1");

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }


    @Test
    void generatorFailure() {
        GenCommand command = new GenCommand(options -> {
            throw new IllegalArgumentException("Внутренняя ошибка");
        });

        Response response = execute(command);

        assertTrue(response.text().contains(
                "Не удалось сгенерировать пароль"
        ));

        assertFalse(response.text().contains(
                "Внутренняя ошибка"
        ));
    }

    @Test
    void duplicateFlags() {
        FakeGenerator fake = new FakeGenerator();
        GenCommand command = new GenCommand(fake);

        Response response = execute(
                command, "16", "--digits", "--digits"
        );

        assertTrue(response.text().contains("Ошибка"));
        assertNull(fake.received);
    }

}
