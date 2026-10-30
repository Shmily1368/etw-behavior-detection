package NU.ETWRealTimeDetector.KafkaProcessor.Threat;

import NU.ETWRealTimeDetector.SysConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;

public class ThreatTest {
    private ObjectMapper objectMapper = new ObjectMapper();

    @Before
    public void setup() {
        SysConfig.setString("RedisHost", "127.0.0.1");
        SysConfig.setInteger("RedisPort", 6379);
        SysConfig.setString("RedisPassword", "");
    }

    @Test
    public void check() throws IOException {
        Threat.init();

        //String log = "{\"policy_id\":\"2\",\"log_name\":\"Process\",\"level\":0,\"ipv6_address\":\"fe80::3836:defa:7744:781a\",\"os_version\":\"Windows10Education\",\"operation_mode\":0,\"source\":\"Agent\",\"ip_address\":\"127.0.0.1\",\"event_category\":\"\",\"uuid\":\"36f46fb3176b2e2f946da25b97d0ac91\",\"mac\":\"00-0C-29-A5-9A-88\",\"result\":1,\"log_category\":\"Process\",\"os_type\":1,\"arguments\":{\"parent_process_id\":4080,\"process_id\":1764,\"product\":\"TcpView\",\"sha256\":\"BACD0C170F71B7FF1B13806EDDC2A2EB05DF6F791D91DEB24E086A633D140652\",\"parent_process_name\":\"explorer.exe\",\"parent_process_user\":\"fanbo\",\"parent_process_commandline\":\"C:\\\\WINDOWS\\\\Explorer.EXE\",\"stater\":\"\",\"process_commandline\":\"\\\"C:\\\\Users\\\\fanbo\\\\Desktop\\\\tcpview.exe\\\"\",\"process_name\":\"tcpview.exe\",\"process_uuid\":\"998EE040|1764\",\"parent_process_uuid\":\"AACB2840|4080\",\"company\":\"Sysinternals-www.sysinternals.com\",\"process_path\":\"C:\\\\Users\\\\fanbo\\\\Desktop\\\\tcpview.exe\",\"parent_process_path\":\"C:\\\\Windows\\\\explorer.exe\",\"parent_process_md5\":\"e9c50a5afdc02626823c8c00c39b7851\",\"session_uuid\":\"01d7e5a28ca58a88|1\",\"signer\":\"MicrosoftCorporation\",\"desc\":\"SysinternalsTcpView\",\"md5\":\"54b671de4a617dbbdcf66939611b00c7\"},\"id\":\"2FBC4B68-7AF5-4208-9080-CCCB34891715\",\"operating\":\"Created\",\"terminate\":0,\"event\":false,\"behavior\":0,\"user\":\"fanbo\",\"host_name\":\"DESKTOP-LAQLVIE\",\"timestamp\":1638265845000}";
        String log="{\"policy_id\":\"2\",\"level\":1,\"log_name\":\"RemoteLogin\",\"os_version\":\"CentOSrelease6.2(Final)Linux\",\"operation_mode\":0,\"ip_address\":\"127.0.0.1\",\"source\":\"Agent\",\"event_category\":\"\",\"uuid\":\"2096f6af041646d583dc11cd5d262577000c2908e131\",\"mac\":\"00-0C-29-08-E1-31\",\"result\":1,\"log_category\":\"Login\",\"os_type\":2,\"arguments\":{\"remote_ip\":\"127.0.0.1\",\"login_type\":\"SSH\",\"login_time\":\"2021-11-3015:31:32\",\"remote_hostname\":\"\",\"user\":\"root\",\"session_uuid\":\"1638257465-pts5\"},\"id\":\"7822aa21-48b9-4313-9e90-a87e116e5249\",\"operating\":\"Logout\",\"terminate\":0,\"event\":false,\"behavior\":0,\"user\":\"root\",\"host_name\":\"localhost.localdomain\",\"timestamp\":1638257492192}";
        HashMap map = objectMapper.readValue(log, HashMap.class);
        Threat.check(map);
    }
}