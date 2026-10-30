package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Test;

import java.io.IOException;

public class RegisterTest {

    @Test
    public void run() throws IOException {
        //SysConfig.load("DebugConfig.xml");
        SysConfig.setString("RegisterUrl", "http://127.0.0.1:8899/api/client/internal-server/register?serverType=detector");

        Register register = new Register();
        register.run();
    }
}