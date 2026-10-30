package NU.ETWRealTimeDetector.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Register extends Thread {
    private static boolean run = true;
    private static int counter = 1;
    private static Logger logger = LoggerFactory.getLogger(Register.class);

    @Override
    public void run() {
        super.run();
        logger.info("register start.");
        while (run) {
            logger.info("try register {}", counter++);
            boolean success = HttpSender.register();
            if (success) {
                logger.info("register success.");
                run = false;
                continue;
            }

            try {
                logger.info("register failed, sleep 60s");
                Thread.sleep(60 * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
        logger.info("register end.");
    }
}
