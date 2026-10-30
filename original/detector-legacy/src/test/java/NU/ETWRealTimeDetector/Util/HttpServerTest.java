package NU.ETWRealTimeDetector.Util;

import org.junit.Test;

import static org.junit.Assert.*;

public class HttpServerTest {

    @Test
    public void run() {
        for (int i = 0; i < 2; i++) {
            new Thread(() -> {
                while (true) {
                    long bac = 1000000;
                    bac = bac >> 1;
                }
            }).start();
            ;
        }
        HttpServer httpServer = new HttpServer();
        httpServer.run();
    }
}