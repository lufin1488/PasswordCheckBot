
package ru.urfu.passwordcheck.command;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GenIntegrationTest {

    private final CommandMessageHandler handler =
            new CommandMessageHandler(DefaultCommands.createRegistry());

    @Test
    void generateDefaultPassword() {
        Response response = handler.handle(1L, "/gen");

        System.out.println("Команда: /gen");
        System.out.println(response.text());

        String password = response.text()
                .replace("Сгенерированный пароль:\n", "");

        assertEquals(16, password.length());
    }

    @Test
    void generateWithOptions() {
        Response response = handler.handle(
                1L, "/gen 20 --letters --digits"
        );

        System.out.println("Команда: /gen 20 --letters --digits");
        System.out.println(response.text());

        String password = response.text()
                .replace("Сгенерированный пароль:\n", "");

        assertEquals(20, password.length());
        assertTrue(password.matches("[a-zA-Z0-9]+"));
    }

    @Test
    void invalidLength() {
        Response response = handler.handle(1L, "/gen 5");

        System.out.println("Команда: /gen 5");
        System.out.println(response.text());

        assertTrue(response.text().contains("Ошибка"));
    }

    @Test
    void helpCommand() {
        Response response = handler.handle(1L, "/help gen");

        System.out.println("Команда: /help gen");
        System.out.println(response.text());

        assertTrue(response.text().contains("/gen"));
    }
}
