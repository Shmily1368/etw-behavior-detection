package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Event.EventType;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.LinkedList;
import java.util.List;

public class TransGrammarTest {
    String transGrammarFile = "TransGrammarTest.txt";
    @Before
    public void setup() throws IOException {
        PrintWriter pw = new PrintWriter(new FileWriter(transGrammarFile));
        pw.println("PT1,FILE_WRITE,FT1,D");
        pw.println("PT3,FILE_READ,FT1,R");
        pw.println("PT5/PT6/PT7,FILE_READ,FT1,D");
        pw.println("PT19,PROCESS_START,PT5/PT6,R");
        pw.close();
    }
    @Test
    public void test1() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.PT1, EventType.FILE_WRITE, TransDirection.DIRECT);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{ add(new TransGrammarEntry("PT1,FILE_WRITE,FT1,D", LabelType.PT1, EventType.FILE_WRITE, LabelType.FT1, TransDirection.DIRECT));
        }};
        assert list.equals(listExpect);
    }

    @Test
    public void test2() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.FT1, EventType.FILE_READ, TransDirection.REVERSE);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{
            add(new TransGrammarEntry("PT3,FILE_READ,FT1,R", LabelType.PT3, EventType.FILE_READ, LabelType.FT1, TransDirection.REVERSE));
        }};
        assert list.equals(listExpect);
    }

    @Test
    public void test3() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.PT5, EventType.FILE_READ, TransDirection.DIRECT);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{
            add(new TransGrammarEntry("PT5/PT6/PT7,FILE_READ,FT1,D", LabelType.PT5, EventType.FILE_READ, LabelType.FT1, TransDirection.DIRECT));
        }};
        assert list.equals(listExpect);
    }

    @Test
    public void test4() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.PT6, EventType.FILE_READ, TransDirection.DIRECT);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{
            add(new TransGrammarEntry("PT5/PT6/PT7,FILE_READ,FT1,D", LabelType.PT6, EventType.FILE_READ, LabelType.FT1, TransDirection.DIRECT));
        }};
        assert list.equals(listExpect);
    }

    @Test
    public void test5() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.PT5, EventType.PROCESS_START, TransDirection.REVERSE);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{
            add(new TransGrammarEntry("PT19,PROCESS_START,PT5/PT6,R", LabelType.PT19, EventType.PROCESS_START, LabelType.PT5, TransDirection.REVERSE));
        }};
        assert list.equals(listExpect);
    }

    @Test
    public void test6() {
        TransGrammar grammar = new TransGrammar(transGrammarFile);
        TransGrammarKey key = new TransGrammarKey(LabelType.PT6, EventType.PROCESS_START, TransDirection.REVERSE);
        List<TransGrammarEntry> list = grammar.getTransGrammar(key);
        List<TransGrammarEntry> listExpect = new LinkedList<TransGrammarEntry>() {{
            add(new TransGrammarEntry("PT19,PROCESS_START,PT5/PT6,R", LabelType.PT19, EventType.PROCESS_START, LabelType.PT6, TransDirection.REVERSE));
        }};
        assert list.equals(listExpect);
    }

    @After
    public void tearDown() {
        File file = new File(transGrammarFile);
        file.delete();
    }
}
