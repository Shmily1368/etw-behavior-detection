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
import java.util.Base64;
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
public final class EventToPlainText {

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

        StringBuilder builder = new StringBuilder();

        PrintWriter printWriter = new PrintWriter(new FileOutputStream(new File("new.data")));

        try (Scanner scanner = new Scanner(new FileReader("2019-12-17-16-20-11.out"))) {
            int i = 1;
            while (scanner.hasNextLine()) {
                if (i % 1000 == 0) {
                    System.out.println(i);
                }
                if (builder.length() > 0) {
                    builder.delete(0, builder.length());
                }
                builder.append(scanner.nextLine());
                //System.out.println(builder.toString());
                try {
                    Map<String, Object> jsonMap = JsonToMap.toMap(builder.toString());
                    String str = jsonMapToString(jsonMap);
                    printWriter.println(str);

                } catch (Exception e) {
                    System.err.println(builder.toString());
                }

                i++;
            }
        } catch (Exception e) {
            System.err.println(builder.toString());
        }

        printWriter.flush();
        printWriter.close();

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
                        //eventBuilder.append(encoder.encodeToString(jsonElement.getAsString().getBytes()));
                        eventBuilder.append(jsonElement.getAsString());
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
