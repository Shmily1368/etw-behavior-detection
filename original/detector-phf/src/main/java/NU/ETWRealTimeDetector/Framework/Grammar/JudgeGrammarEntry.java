package NU.ETWRealTimeDetector.Framework.Grammar;


import NU.ETWRealTimeDetector.Framework.Label.LabelType;

import java.util.Set;

public class JudgeGrammarEntry {
    private Set<LabelType> requirement;
    private boolean shouldExists;

    public JudgeGrammarEntry(Set<LabelType> requirement, boolean shouldExists) {
        this.requirement = requirement;
        this.shouldExists = shouldExists;
    }

    public Set<LabelType> getRequirement() {
        return requirement;
    }

    public boolean shouldExists() {
        return shouldExists;
    }


}

