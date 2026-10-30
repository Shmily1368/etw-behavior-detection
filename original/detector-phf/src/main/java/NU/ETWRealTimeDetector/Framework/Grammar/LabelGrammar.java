package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;

public class LabelGrammar {
    private Logger logger = LoggerFactory.getLogger(LabelGrammar.class);

    private Map<LabelType, LabelGrammarEntry> grammarMap = new HashMap<>();

    private List<LabelGrammarEntry> labelGrammarEntries = new ArrayList<>();

    public LabelGrammar(String fileName) {
        try (Scanner scanner = new Scanner(new FileReader(fileName))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                String[] splitLine = line.split(",");
                LabelType type = LabelType.valueOf(splitLine[0]);
                double suspiciousScore = Double.parseDouble(splitLine[1]);
                double confidenceScore = Double.parseDouble(splitLine[2]);
                LabelCategory category = LabelCategory.valueOf(splitLine[3]);
                String description = splitLine[4];
                LabelGrammarEntry entry = new LabelGrammarEntry(type, suspiciousScore, confidenceScore, category, description);
                this.grammarMap.put(type, entry);

                if (category == LabelCategory.PHF) {
                    LabelType.addPhfLabel(type);
                }
                if (category == LabelCategory.TRUE) {
                    labelGrammarEntries.add(entry);
                }
            }
        } catch (Exception e) {
            logger.error("read label grammar failed", e);
        }
    }

    public LabelGrammarEntry getGrammar(LabelType type) {
        return grammarMap.get(type);
    }

    public List<LabelGrammarEntry> getTrueGrammarEntries() {
        return labelGrammarEntries;
    }
}
