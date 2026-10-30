package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class LabelGrammarTest {

    private String labelGrammarFile = "LabelGrammarTest.txt";

    @Before
    public void setup() throws IOException {
        PrintWriter pw = new PrintWriter(new FileWriter(labelGrammarFile));
        pw.println("PT1,0,0.1,TRUE,The process has network connections.");
        pw.println("PT2,1,1,PHF,Access sensitive information");
        pw.println("PT3,0,0.5,CODE_SOURCE,Access data from network.");
        pw.println("PT10,0,1,FEATURE,Its parent or ancestor process has network connection.");
        pw.println("PT17,0,1,FALSE,be injected by untrusted code.");
        pw.close();
    }

    @Test
    public void test1() {
        LabelGrammar grammar = new LabelGrammar(labelGrammarFile);
        List<LabelGrammarEntry> trueGrammars = grammar.getTrueGrammarEntries();
        List<LabelGrammarEntry> trueGrammarsExpected = new ArrayList<LabelGrammarEntry>(){{
            add(new LabelGrammarEntry(LabelType.PT1, 0, 0.1, LabelCategory.TRUE, "The process has network connections."));
        }};

        assert trueGrammars.equals(trueGrammarsExpected);
    }

    @Test
    public void test2() {
        LabelGrammar grammar = new LabelGrammar(labelGrammarFile);
        LabelGrammarEntry entry = grammar.getGrammar(LabelType.PT2);
        LabelGrammarEntry entryExpected = new LabelGrammarEntry(LabelType.PT2, 1, 1, LabelCategory.PHF, "Access sensitive information");

        assert entry.equals(entryExpected);
    }

    @Test
    public void test3() {
        LabelGrammar grammar = new LabelGrammar(labelGrammarFile);
        LabelGrammarEntry entry = grammar.getGrammar(LabelType.PT3);
        LabelGrammarEntry entryExpected = new LabelGrammarEntry(LabelType.PT3, 0, 0.5, LabelCategory.CODE_SOURCE, "Access data from network.");

        assert entry.equals(entryExpected);
    }

    @After
    public void tearDown() {
        File file = new File(labelGrammarFile);
        file.delete();
    }
}
