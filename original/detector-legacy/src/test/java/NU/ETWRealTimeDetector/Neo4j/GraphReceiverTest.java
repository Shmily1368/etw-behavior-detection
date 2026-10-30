package NU.ETWRealTimeDetector.Neo4j;

import NU.ETWRealTimeDetector.CompilationConfig;
import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class GraphReceiverTest {

    @Before
    public void setConfig() {
        CompilationConfig.DEBUG = true;
        SysConfig.setString("KafkaBrokerServer", "127.0.0.1:9092");
        SysConfig.setString("ReceiveGraphTopic", "graph_dev");
    }


    @Test
    public void run() {
        GraphReceiver receiver = new GraphReceiver();
        receiver.run();
    }
}