package ru.urfu.passwordcheck.strength;
import java.util.List;
public record StrengthResult(StrengthLevel level, List<String> reasons) {
    public StrengthResult{
        if (level==null){
            throw new IllegalArgumentException("Некорректный уровень");
        }
        reasons=List.copyOf(reasons);
    }
}
