package magicshield;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;

import org.xerial.snappy.Snappy;

/**
 *  读取标准json文件，处理成 字符串格式事件，并按规则分组，保存到文件
 */
public final class App {
    private App() {
    }

    static StringBuilder eventBuilder = new StringBuilder();
    static List<String> fileds = Arrays.asList("TimeStamp", "processID", "threadID", "EventName", "arguments");
    static final String Whitespace = " ";
    static final String Delimiter = "=";

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        // 每个数据块的数量，默认10000 
        int groupSize = 1000;
        StringBuilder groupBuilder = new StringBuilder();
        StringBuilder builder = new StringBuilder();

        PrintWriter printWriter = new PrintWriter(new FileOutputStream(new File("new.data")));
        // java对象数据块序列化后的二进制文件
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("datablock"));

        List<DataBlock> list = new ArrayList<>();

        long startUpTime = 0;

        long groupEndTime = 0;
        long lastGroupEndTime = 0;
        long lastSendTime = 0;
        try (Scanner scanner = new Scanner(new FileReader("2019-07-06-15-10-35.out"))) {
            int i = 1;
            while (scanner.hasNextLine()) {
                if (builder.length() > 0) {
                    builder.delete(0, builder.length());
                }
                builder.append(scanner.nextLine());
                //System.out.println(builder.toString());
                try {
                    Map<String, Object> jsonMap = JsonToMap.toMap(builder.toString());
                    String str = jsonMapToString(jsonMap);
                    //printWriter.println(str);
                    groupBuilder.append(str);

                    String endTimeStr = str.split(" ")[0];
                    long eventTime = Long.valueOf(endTimeStr) / 1000000000;

                    if (startUpTime == 0 && eventTime > 0) {
                        startUpTime = eventTime;
                    }

                    if (groupEndTime == 0 && eventTime > 0) {
                        groupEndTime = (lastGroupEndTime == 0 ? eventTime : lastGroupEndTime) + 5;
                    }

                    if (groupSize % 10000 == 0 || eventTime > groupEndTime) {
                        printWriter.write(groupBuilder.toString());
                        printWriter.write(System.lineSeparator());

                        DataBlock dataBlock = new DataBlock();
                        dataBlock.sendTime = (lastSendTime == 0 ? eventTime : lastSendTime + 5) - startUpTime;
                        dataBlock.eventCount = groupSize;
                        dataBlock.data = Snappy.compress(groupBuilder.toString());
                        dataBlock.dataSize = dataBlock.data.length;

                        list.add(dataBlock);

                        lastSendTime = lastSendTime == 0 ? eventTime : lastSendTime + 5;
                        lastGroupEndTime = groupEndTime;
                        groupEndTime = 0;
                        groupSize = 0;
                        groupBuilder.delete(0, groupBuilder.length());
                    } else {
                        groupBuilder.append(System.lineSeparator());
                    }
                } catch (Exception e) {
                    System.err.println(builder.toString());
                }

                i++;
                groupSize++;
            }
        } catch (Exception e) {
            System.err.println(builder.toString());
        }

        printWriter.write(groupBuilder.toString());
        printWriter.flush();
        printWriter.close();

        DataBlock dataBlock = new DataBlock();
        dataBlock.sendTime = lastSendTime + 5 - startUpTime;
        dataBlock.eventCount = groupSize;
        dataBlock.data = Snappy.compress(groupBuilder.toString());
        dataBlock.dataSize = dataBlock.data.length;
        list.add(dataBlock);

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
                        eventBuilder.append(URLEncoder.encode(jsonElement.getAsString(), "UTF8"));
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
}
