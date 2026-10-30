package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;
import java.util.HashMap;

public class HttpServer extends Thread {
//    private static Logger healthLogger = LoggerFactory.getLogger("health");
//    private static Gson gson = new Gson();
//    private static final int httpServerPort = SysConfig.getInteger("HttpServerPort", 8080);
//    private static final String newLine = "\r\n";

    @Override
    public void run() {
        System.err.println("HttpServer 已废弃");
//        String response = "unsupported instruction";
//        try (ServerSocket socket = new ServerSocket(httpServerPort)) {
//            while (true) {
//                Socket connection = socket.accept();
//                try {
//                    BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
//                    OutputStream out = new BufferedOutputStream(connection.getOutputStream());
//                    PrintStream pout = new PrintStream(out);
//
//                    // read first line of request
//                    String request = in.readLine();
//                    if (request == null)
//                        continue;
//
//                    // we ignore the rest
//                    while (true) {
//                        String ignore = in.readLine();
//                        if (ignore == null || ignore.length() == 0)
//                            break;
//                    }
//                    if (!request.startsWith("GET ") || !(request.endsWith(" HTTP/1.0") || request.endsWith(" HTTP/1.1"))) {
//                        // bad request
//                        pout.print("HTTP/1.0 400 Bad Request" + newLine + newLine);
//                    } else if (request.startsWith("GET /health")) {
//                        HashMap<String, String> info = MemoryInfo.currentMemoryInfo();
//                        response = gson.toJson(info);
//                        pout.print("HTTP/1.0 200 OK" + newLine + "Content-Type: application/json" + newLine + "Date: " + new Date() + newLine + "Content-length: " + response.length() + newLine + newLine + response);
//                        healthLogger.info(response);
//                    } else {
//                        System.out.println(request);
//                        if (request.contains("shutdown")) {
//                            response = "shutting down...";
//                            ShutdownManager.shutdown();
//                        }
//                        pout.print("HTTP/1.0 200 OK" + newLine + "Content-Type: text/plain" + newLine + "Date: " + new Date() + newLine + "Content-length: " + response.length() + newLine + newLine + response);
//                    }
//
//                    pout.close();
//                } catch (Exception e) {
//                    System.err.println("Error handling request: " + e);
//                }
//
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

    }
}
