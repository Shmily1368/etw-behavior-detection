package NU.ETWRealTimeDetector.IPC;

import NU.ETWRealTimeDetector.CompilationConfig;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HealthCheckReporter {
    private static ExecutorService pool = Executors.newSingleThreadExecutor();
    private static Gson gson = new Gson();

    public static void report(String checkId, String clientId) {

        Map<String, String> params = new HashMap<>();
        params.put("action", "health_check");
        params.put("check_id", checkId);
        params.put("err_type", "0");
        params.put("client_id", clientId);
        pool.execute(new HealthCheckMessage(gson.toJson(params)));
    }


    private static class HealthCheckMessage implements Runnable {

        private final String message;

        HealthCheckMessage(String message) {
            this.message = message;
        }

        @Override
        public void run() {
        }
    }
}
