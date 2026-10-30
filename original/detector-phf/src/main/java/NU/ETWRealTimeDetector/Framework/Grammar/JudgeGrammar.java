package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;
import java.util.stream.Collectors;

public class JudgeGrammar {
    private LinkedHashMap<String, List<JudgeGrammarEntry>> grammar = new LinkedHashMap<>();
    private Map<String, Integer> judgeMode2AlertLevel = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(JudgeGrammar.class);

    public JudgeGrammar(String fileName) {
        try (Scanner scanner = new Scanner(new FileReader(fileName))) {
            while (scanner.hasNextLine()) {
                String judgeModeName = scanner.nextLine();
                List<JudgeGrammarEntry> requirements = new ArrayList<>();
                while (true) {
                    String line = scanner.nextLine();
                    if ("0".equals(line)) {
                        break;
                    }
                    boolean shouldExists = !line.startsWith("!");
                    String[] splitLine = line.replace("!", "").split("/");
                    Set<LabelType> oneRequirement = new HashSet<>();
                    for (String s : splitLine) {
                        oneRequirement.add(LabelType.valueOf(s));
                    }
                    JudgeGrammarEntry entry = new JudgeGrammarEntry(oneRequirement, shouldExists);
                    requirements.add(entry);
                }
                grammar.put(judgeModeName, requirements);
            }
        } catch (Exception e) {
            logger.error("read judge grammar failed", e);
        }

        int index = 1;
        for (String judgeMode : grammar.keySet()) {
            judgeMode2AlertLevel.put(judgeMode, index++);
        }
    }


    public String judge(Set<LabelType> labelTypes) {
        if (labelTypes == null || labelTypes.isEmpty()) {
            return "";
        }

        for (String judgeMode : grammar.keySet()) {
            List<JudgeGrammarEntry> entries = grammar.get(judgeMode);
            boolean matchesThisMode = true;
            for (JudgeGrammarEntry entry : entries) {
                boolean shouldExists = entry.shouldExists();
                Set<LabelType> requirement = entry.getRequirement();
                if (shouldExists == Collections.disjoint(labelTypes, requirement)) {
                    matchesThisMode = false;
                    break;

                }
            }
            if (matchesThisMode) {
                return judgeMode;
            }
        }
        return "";
    }

    public Set<LabelType> getLabelTypeSetByJudgeMode(String judgeMode) {
        return grammar.get(judgeMode).stream()
                .filter(judgeGrammarEntry -> judgeGrammarEntry.shouldExists())
                .map(l -> l.getRequirement())
                .flatMap(l -> l.stream())
                .collect(Collectors.toSet());
    }

    public Map<String, Integer> getJudgeMode2AlertLevel() {
        return judgeMode2AlertLevel;
    }
}
