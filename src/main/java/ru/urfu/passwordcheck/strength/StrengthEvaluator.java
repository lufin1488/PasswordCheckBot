package ru.urfu.passwordcheck.strength;

public interface StrengthEvaluator {
    StrengthResult evaluate (String password);
}
