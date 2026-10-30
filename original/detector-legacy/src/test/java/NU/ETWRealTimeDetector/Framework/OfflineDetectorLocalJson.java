package NU.ETWRealTimeDetector.Framework;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.KafkaProcessor.MessageProcessor;
import NU.ETWRealTimeDetector.Neo4j.Neo4jClient;
import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.Scanner;

public class OfflineDetectorLocalJson {
    static int i = 1;
    static String line = "";

    @Before
    public void setConfig() {
        SysConfig.setInteger("ProcessRetentionTime", 30);
        CompilationConfig.DEBUG = true;
    }

    @Test
    public void read() {
        String clientId = "IntegrationTest_simulator0";
        MessageProcessor processor = new MessageProcessor(null);
        processor.setCurrent(clientId);
        try (Scanner scanner = new Scanner(new FileReader("outputtest.json"))) {
            line = scanner.nextLine();
            if (i % 10000 == 0) {
                System.out.println(i);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }


        // check result

    }
}
