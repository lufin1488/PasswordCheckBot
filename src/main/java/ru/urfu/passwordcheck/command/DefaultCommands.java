
package ru.urfu.passwordcheck.command;

import ru.urfu.passwordcheck.command.impl.AboutCommand;
import ru.urfu.passwordcheck.command.impl.AuthorCommand;
import ru.urfu.passwordcheck.command.impl.GenCommand;
import ru.urfu.passwordcheck.command.impl.HelpCommand;
import ru.urfu.passwordcheck.generator.SecurePasswordGenerator;

public final class DefaultCommands {

    private DefaultCommands() {
    }

    public static CommandRegistry createRegistry() {
        CommandRegistry registry = new CommandRegistry();

        registry.register(new AboutCommand());
        registry.register(new AuthorCommand());
        registry.register(new GenCommand(new SecurePasswordGenerator()));
        registry.register(new HelpCommand(registry));

        return registry;
    }
}
