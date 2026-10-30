package NU.ETWRealTimeDetector.Framework.Grammar;

import NU.ETWRealTimeDetector.Framework.Label.LabelForCS;
import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Framework.Node.Node;
import NU.ETWRealTimeDetector.Framework.Node.ProcessNode;
import NU.ETWRealTimeDetector.Process.Process;
import NU.ETWRealTimeDetector.Process.ProcessTable;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class JudgeGrammarTest {

    String judgeGrammarFile = "JudgeGrammarTest.txt";

    @Before
    public void setup() throws IOException {
        PrintWriter pw = new PrintWriter(new FileWriter(judgeGrammarFile));
        pw.println("Download&Exec");
        pw.println("PT18");
        pw.println("PT22/PT23");
        pw.println("PT5/PT6/PT7/PT8/PT9/PT12/PT16");
        pw.println("!PF1");
        pw.println("0");
        pw.println("ExistingMalware");
        pw.println("PT18");
        pw.println("PT5/PT6/PT7/PT8/PT9/PT12/PT16");
        pw.println("!PF1");
        pw.println("0");
        pw.close();
    }

    @Test
    public void test1() {
        /*
        JudgeGrammar grammar = new JudgeGrammar(judgeGrammarFile);
        ProcessTable processTable = ProcessTable.getInstance("weihaoPC");
        Process process = processTable.getProcessOrCreateOneIfNotExist(1234, 1000L);
        Node node = new ProcessNode(process);
        node.getLabelList().put(LabelType.PT18, new LabelForCS(LabelType.PT18, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT22, new LabelForCS(LabelType.PT22, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT5, new LabelForCS(LabelType.PT5, "weihaoPC", process.getUuid(), 1000L, ""));

        String result = grammar.judge(node.getLabelList().keySet());
        assert "Download&Exec".equals(result);
        */
    }

    @Test
    public void test2() {
        /*
        JudgeGrammar grammar = new JudgeGrammar(judgeGrammarFile);
        ProcessTable processTable = ProcessTable.getInstance("weihaoPC");
        Process process = processTable.getProcessOrCreateOneIfNotExist(1234, 1000L);
        Node node = new ProcessNode(process);
        node.getLabelList().put(LabelType.PT18, new LabelForCS(LabelType.PT18, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT23, new LabelForCS(LabelType.PT23, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT16, new LabelForCS(LabelType.PT16, "weihaoPC", process.getUuid(), 1000L, ""));

        String result = grammar.judge(node.getLabelList().keySet());
        assert "Download&Exec".equals(result);
        */
    }

    @Test
    public void test3() {
        /*
        JudgeGrammar grammar = new JudgeGrammar(judgeGrammarFile);
        ProcessTable processTable = ProcessTable.getInstance("weihaoPC");
        Process process = processTable.getProcessOrCreateOneIfNotExist(1234, 1000L);
        Node node = new ProcessNode(process);
        node.getLabelList().put(LabelType.PT18, new LabelForCS(LabelType.PT18, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT22, new LabelForCS(LabelType.PT22, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PF1, new LabelForCS(LabelType.PF1, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT5, new LabelForCS(LabelType.PT5, "weihaoPC", process.getUuid(), 1000L, ""));

        String result = grammar.judge(node.getLabelList().keySet());
        assert "".equals(result);
        */
    }

    @Test
    public void test4() {
        /*
        JudgeGrammar grammar = new JudgeGrammar(judgeGrammarFile);
        ProcessTable processTable = ProcessTable.getInstance("weihaoPC");
        Process process = processTable.getProcessOrCreateOneIfNotExist(1234, 1000L);
        Node node = new ProcessNode(process);
        node.getLabelList().put(LabelType.PT18, new LabelForCS(LabelType.PT18, "weihaoPC", process.getUuid(), 1000L, ""));
        node.getLabelList().put(LabelType.PT5, new LabelForCS(LabelType.PT5, "weihaoPC", process.getUuid(), 1000L, ""));

        String result = grammar.judge(node.getLabelList().keySet());
        assert "ExistingMalware".equals(result);
        */
    }

    @After
    public void tearDown() {
        File file = new File(judgeGrammarFile);
        file.delete();
    }
}
