package NU.ETWRealTimeDetector.Util;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.Test;

import java.io.*;
import java.math.BigDecimal;
import java.util.Scanner;


public class DeduplicatingEventTest {

    Gson gson = new Gson();
    JsonParser parser = new JsonParser();
    StringBuilder builder = new StringBuilder();
    boolean exist = false;
    int duplicateCount = 0;

    @Test
    public void deduplicate() throws IOException {
        DeduplicatingEvent deduplicatingEvent = new DeduplicatingEvent("test");
        int i = 1;
        BufferedWriter bw = new BufferedWriter(new FileWriter("outputtestnew.out", false));
        try (Scanner scanner = new Scanner(new FileReader("/Users/wangshifeng/Desktop/work/gitlab/wangshifeng/simulator/2019-10-21-20-53-08.out"))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (i % 10000 == 0) {
                    System.out.println(i + "=>" + (i - duplicateCount) + " duplicates:" + duplicateCount);
                }
                try {
                    JsonObject jsonObj = parser.parse(line).getAsJsonObject();
                    String eventType = "";

                    if (jsonObj.has("EventName")) {
                        JsonElement eventElement = jsonObj.get("EventName");
                        eventType = eventElement.getAsString();
                    } else {
                        JsonElement callStackElement = jsonObj.get("CallStack");
                        eventType = callStackElement.getAsString();
                    }

                    // init
                    builder.delete(0, builder.length());
                    exist = false;
                    switch (eventType) {
                        case "VisibleWindowInfo": {
                            builder.append(jsonObj.get("processID").getAsString());

                            break;
                        }
                        case "UdpIpRecvIPV4":
                        case "UdpIpSendIPV4":
                        case "TcpIpRecvIPV4":
                        case "TcpIpSendIPV4":
                        case "TcpIpDisconnectIPV4":
                        case "TcpIpConnectIPV4":
                            builder.append(jsonObj.get("processID").getAsString());
                            JsonObject argumentElement = (JsonObject) jsonObj.get("arguments");
                            builder.append(argumentElement.get("daddr").getAsString());
                            exist = deduplicatingEvent.exist(builder);
                            break;
                        case "DNSQueryRequest":
                            builder.append(jsonObj.get("processID").getAsString());
                            argumentElement = (JsonObject) jsonObj.get("arguments");
                            builder.append(argumentElement.get("QueryDomainName").getAsString());
                            exist = deduplicatingEvent.exist(builder);
                            break;
                        case "FileIoRead":
                        case "FileIoWrite":
                            builder.append(jsonObj.get("processID").getAsString());
                            builder.append(eventType);
                            argumentElement = (JsonObject) jsonObj.get("arguments");
                            builder.append(argumentElement.get("FileName").getAsString());
                            exist = deduplicatingEvent.exist(builder);
                            break;
                        case "ScreenGrab":
                        case "Keylogger":
                            builder.append(jsonObj.get("processID").getAsString());
                            builder.append(eventType);
                            exist = deduplicatingEvent.exist(builder);
                            break;
                        case "FileIoRename":
                            builder.append(jsonObj.get("processID").getAsString());
                            builder.append(eventType);
                            argumentElement = (JsonObject) jsonObj.get("arguments");
                            builder.append(argumentElement.get("FileName").getAsString());
                            builder.append(argumentElement.get("NewFileName").getAsString());
                            break;

                    }

                    if (exist) {
                        duplicateCount++;
                        continue;
                    }
                    bw.write(line);
                    bw.newLine();
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    i++;
                }
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        bw.flush();
        bw.close();

        System.out.println("total:" + i);
        System.out.println("duplicates:" + duplicateCount);
    }

    @Test
    public void exist() throws IOException, InterruptedException {
        DeduplicatingEvent deduplicatingEventA = new DeduplicatingEvent("test");
        DeduplicatingEvent deduplicatingEventB = new DeduplicatingEvent("test");
        StringBuilder builder = new StringBuilder();
        //ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        //Writer writer = new OutputStreamWriter(outputStream);
        //writer.write("a");
        //deduplicatingEvent.exist(outputStream);

        //outputStream.reset();
        //writer.write("a");
        //assertTrue(deduplicatingEvent.exist(outputStream));
        //Thread.sleep(7000);
        //assertTrue(deduplicatingEvent.exist(outputStream));
        //Thread.sleep(5000);
        //assertFalse(deduplicatingEvent.exist(outputStream));


        long start = System.currentTimeMillis();
        boolean res;
        String event = "fdsafjdsajfdklsajfkdsjalfjdlkasjflkdjsalkfjdlksajfkdlasfdajfkdsajreiwruewiourieow4732894hfdshffdafdkjasfdjsakfjdkajfkdajfkdsfjdafjdkasjfdkajsfda";
        int count = 0;
        for (int i = 0; i < 10000000; i++) {
            //outputStream.reset();
            //writer.write(i);
            builder.delete(0, builder.length());
            builder.append(i);
            builder.append(event);
            res = deduplicatingEventA.exist(builder);
            if (res) {
                res = deduplicatingEventB.exist(builder);
                if (!res) {
                    count++;
                    System.out.println(i + " " + res);
                }
            }
            //assertTrue(deduplicatingEvent.exist(outputStream));
        }
        long end = System.currentTimeMillis();
        System.out.println("time:" + (end - start));
        System.out.println("误报:" + count);
        BigDecimal rate = BigDecimal.valueOf(count).divide(BigDecimal.valueOf(10000000));
        System.out.println("误报率:" + rate);
    }
}