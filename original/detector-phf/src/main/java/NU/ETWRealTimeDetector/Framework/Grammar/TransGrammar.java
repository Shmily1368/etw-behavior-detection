package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.util.*;

public class TransGrammar {
    Logger logger = LoggerFactory.getLogger(TransGrammar.class);

    Map<TransGrammarKey, List<TransGrammarEntry>> transGrammarMap = new HashMap<>();

    public TransGrammar(String fileName) {
        try (Scanner scanner = new Scanner(new FileReader(fileName))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if ("".equals(line)) {
                    continue;
                }
                String[] splitLine = line.split(",");
                EventType event = EventType.valueOf(splitLine[1]);
                TransDirection direction = null;
                switch (splitLine[3]) {
                    case "D": direction = TransDirection.DIRECT; break;
                    case "R": direction = TransDirection.REVERSE; break;
                    case "=": direction = TransDirection.TWOWAY; break;
                }
                if (splitLine[0].contains("/")) {
                    LabelType label1 = LabelType.valueOf(splitLine[2]);
                    String[] labels = splitLine[0].split("/");
                    for (String label : labels) {
                        LabelType label0 = LabelType.valueOf(label);
                        String grammar = label0 + "," + event + "," + label1 + ",";
                        switch (direction) {
                            case DIRECT: grammar += "D"; break;
                            case REVERSE: grammar += "R"; break;
                            case TWOWAY: grammar += "="; break;
                        }
                        TransGrammarEntry entry = new TransGrammarEntry(grammar, label0, event, label1, direction);
                        if (direction == TransDirection.DIRECT || direction == TransDirection.TWOWAY) {
                            TransGrammarKey key = new TransGrammarKey(label0, event, TransDirection.DIRECT);
                            List<TransGrammarEntry> grammars = transGrammarMap.getOrDefault(key, new ArrayList<>());
                            grammars.add(entry);
                            transGrammarMap.putIfAbsent(key, grammars);
                        }
                        if (direction == TransDirection.REVERSE || direction == TransDirection.TWOWAY) {
                            TransGrammarKey key = new TransGrammarKey(label1, event, TransDirection.REVERSE);
                            List<TransGrammarEntry> grammars = transGrammarMap.getOrDefault(key, new ArrayList<>());
                            grammars.add(entry);
                            transGrammarMap.putIfAbsent(key, grammars);
                        }
                    }
                } else {
                    LabelType label0 = LabelType.valueOf(splitLine[0]);
                    String[] labels = splitLine[2].split("/");
                    for (String label : labels) {
                        LabelType label1 = LabelType.valueOf(label);
                        String grammar = label0 + "," + event + "," + label1 + ",";
                        switch (direction) {
                            case DIRECT: grammar += "D"; break;
                            case REVERSE: grammar += "R"; break;
                            case TWOWAY: grammar += "="; break;
                        }
                        TransGrammarEntry entry = new TransGrammarEntry(grammar, label0, event, label1, direction);
                        if (direction == TransDirection.DIRECT || direction == TransDirection.TWOWAY) {
                            TransGrammarKey key = new TransGrammarKey(label0, event, TransDirection.DIRECT);
                            List<TransGrammarEntry> grammars = transGrammarMap.getOrDefault(key, new ArrayList<>());
                            grammars.add(entry);
                            transGrammarMap.putIfAbsent(key, grammars);
                        }
                        if (direction == TransDirection.REVERSE || direction == TransDirection.TWOWAY) {
                            TransGrammarKey key = new TransGrammarKey(label1, event, TransDirection.REVERSE);
                            List<TransGrammarEntry> grammars = transGrammarMap.getOrDefault(key, new ArrayList<>());
                            grammars.add(entry);
                            transGrammarMap.putIfAbsent(key, grammars);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("read trans grammar failed", e);
        }
    }

    public List<TransGrammarEntry> getTransGrammar(TransGrammarKey key) {
        return transGrammarMap.getOrDefault(key, new ArrayList<>());
    }
}