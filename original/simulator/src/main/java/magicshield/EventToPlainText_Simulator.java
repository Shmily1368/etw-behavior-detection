package magicshield;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.GZIPOutputStream;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

import org.xerial.snappy.Snappy;

/**
 *  读取标准json文件，处理成 字符串格式事件，并按规则分组，保存到文件
 */
public final class EventToPlainText_Simulator {

    static StringBuilder eventBuilder = new StringBuilder();
    static List<String> fileds = Arrays.asList("TimeStamp", "processID", "threadID", "EventName", "arguments");
    static final String Whitespace = " ";
    static final String Delimiter = "=";
    static final Base64.Encoder encoder = Base64.getEncoder();

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        // 每个数据块的数量，默认10000
        int groupSize = 10000;
        int groupCount = 0;
        // java对象数据块序列化后的二进制文件
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("datablockWithProto_plaintext"));
        List<DataBlock> list = new ArrayList<>();
        // 第一条事件的时间
        long startUpTimeStamp = 0;

        // 能够分入当前组的事件最大时间
        long groupEndTime = 0;
        long lastGroupEndTime = 0;
        long lastSendTime = 0;
        // 数据块的发送时间，如果触发的是10000条，则发送时间是当前事件时间，如果触发的是10s规则，发送时间=上次发送时间+10s
        long maxTimeStamp = 0;

        StringBuilder groupBuilder = new StringBuilder();

        PrintWriter printWriter = new PrintWriter(new FileOutputStream(new File("new.data")));

        String line = "";
        try (Scanner scanner = new Scanner(new FileReader("2019-12-17-16-20-11.out"))) {
            int i = 1;
            while (scanner.hasNextLine()) {
                if (i % 10000 == 0) {
                    System.out.println(i);
                }

                line = scanner.nextLine();
                try {
                    Map<String, Object> jsonMap = JsonToMap.toMap(line);
                    String str = jsonMapToString(jsonMap);
                    printWriter.println(str);

                    groupBuilder.append(str);
                    groupBuilder.append(System.lineSeparator());

                    // 事件时间
                    long eventTime = Long.valueOf(jsonMap.get("TimeStamp").toString()) / 1000000000;

                    // 获取第一条事件的时间
                    if (startUpTimeStamp == 0 && eventTime > 0) {
                        startUpTimeStamp = eventTime;
                    }

                    if (eventTime > maxTimeStamp) {
                        maxTimeStamp = eventTime;
                    }

                    // 设置能够进入当前组的最大事件时间
                    if (groupEndTime == 0 && eventTime > 0) {
                        // 10s 内的事件分成一个组
                        groupEndTime = (lastGroupEndTime == 0 ? eventTime : lastGroupEndTime) + 10;
                    }
                    // 10s 内的事件分成一个组，或者一个组内事件上限达10000
                    if ((groupCount > 0 && groupCount >= groupSize) || (eventTime > 0 && eventTime >= groupEndTime)) {
                        DataBlock dataBlock = new DataBlock();
                        // 数据块的发送时间，相对第一条事件的时间

                        dataBlock.sendTime = maxTimeStamp - startUpTimeStamp;
                        //dataBlock.sendTime = (lastSendTime == 0 ? eventTime : lastSendTime + 10) - startUpTime;
                        dataBlock.eventCount = groupCount;
                        dataBlock.data = compress(groupBuilder.toString());
                        dataBlock.dataSize = dataBlock.data.length;

                        list.add(dataBlock);

                        lastSendTime = lastSendTime == 0 ? eventTime : lastSendTime + 10;
                        lastGroupEndTime = maxTimeStamp == groupEndTime ? groupEndTime : maxTimeStamp;
                        groupEndTime = 0;
                        groupCount = 0;
                        groupBuilder.delete(0, groupBuilder.length());
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

                i++;
                groupCount++;
            }
        } catch (Exception e) {
            System.err.println(line);
            e.printStackTrace();
        }

        printWriter.flush();
        printWriter.close();

        if (groupBuilder.length() > 0) {
            DataBlock dataBlock = new DataBlock();
            dataBlock.sendTime = maxTimeStamp - startUpTimeStamp;
            dataBlock.eventCount = groupCount;
            dataBlock.data = compress(groupBuilder.toString());
            dataBlock.dataSize = dataBlock.data.length;
            list.add(dataBlock);
        }

        oos.writeObject(list);
        oos.flush();
        oos.close();
        System.out.println(list.stream().map(l -> l.eventCount).reduce((s1, s2) -> s1 + s2).get());
        System.out.println("over.");
    }

    @SuppressWarnings("unchecked")
    public static String jsonMapToString(Map<String, Object> jsonMap) throws UnsupportedEncodingException {
        if (eventBuilder.length() > 0) {
            eventBuilder.delete(0, eventBuilder.length());
        }

        for (String filed : fileds) {
            //eventBuilder.append(Whitespace);
            //eventBuilder.append(filed);
            eventBuilder.append(Whitespace);
            Object value = jsonMap.get(filed);
            if (value == null) {
                if (filed.equals("EventName") && jsonMap.containsKey("CallStack")) {
                    value = jsonMap.get("CallStack");
                }
            }
            if (value instanceof JsonPrimitive) {
                eventBuilder.append(((JsonPrimitive) value).getAsString());
            } else if (value instanceof HashMap) {
                HashMap<String, Object> subObject = (HashMap<String, Object>) value;
                for (Map.Entry<String, Object> subEntry : subObject.entrySet()) {
                    if (subEntry.getValue() instanceof JsonElement) {
                        eventBuilder.append(subEntry.getKey());
                        eventBuilder.append(Delimiter);
                        JsonElement jsonElement = (JsonElement) subEntry.getValue();
                        //eventBuilder.append(URLEncoder.encode(jsonElement.getAsString(), "UTF8"));
                        eventBuilder.append(encoder.encodeToString(jsonElement.getAsString().getBytes()));
                        //eventBuilder.append(jsonElement.getAsString());
                        eventBuilder.append(Whitespace);
                    }
                }
            } else {

            }
        }

        if (eventBuilder.indexOf(Whitespace) == 0) {
            eventBuilder.delete(0, 1);
        }

        return eventBuilder.toString();
    }

    public static byte[] compress(String str) {
        if (str == null || str.length() == 0) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPOutputStream gzip;
        try {
            gzip = new GZIPOutputStream(out);
            gzip.write(str.getBytes("UTF-8"));
            gzip.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return out.toByteArray();
    }
}
