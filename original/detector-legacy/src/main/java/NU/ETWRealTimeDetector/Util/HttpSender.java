package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpSender {
    private static Logger logger = LoggerFactory.getLogger(HttpSender.class);
    private static final String registerUrl = SysConfig.getString("RegisterUrl", "");
    private static Integer successCode = 200;


    public static boolean register() {
        HttpClient client = HttpClientBuilder.create().build();

        HttpPost postRequest = new HttpPost(registerUrl);
        postRequest.setHeader("Content-type", "application/json");
        try {
            HttpResponse response = client.execute(postRequest);
            int statusCode = response.getStatusLine().getStatusCode();
            logger.info("http register result: {}", statusCode);
            if (successCode.equals(statusCode)) {
                return true;
            }
        } catch (Exception e) {
            logger.error("register error", e);
        }
        return false;
    }

}
