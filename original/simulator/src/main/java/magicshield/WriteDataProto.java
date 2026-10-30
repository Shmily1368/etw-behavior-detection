package magicshield;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.protobuf.ByteString;

import org.xerial.snappy.Snappy;

import magicshield.Etwdata.EventRecords;
import magicshield.Etwdata.EventRecords.Builder;

/**
 * 读取标准json文件，构造成record对象，按规则分组，最后保存到文件
 */
public final class WriteDataProto {

    static int i = 1;
    public static Map<String, Object> argument = new HashMap<>();
    static StringBuilder callstackBuilder = new StringBuilder();

    /**
     * Says hello to the world.
     *
     * @param args The arguments of the program.
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {

        // 每个数据块的数量，默认10000
        int groupSize = 10000;
        int groupCount = 0;
        Builder builder = EventRecords.newBuilder();

        // java对象数据块序列化后的二进制文件
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("datablockWithProto"));

        List<DataBlock> list = new ArrayList<>();

        // 第一条事件的时间
        long startUpTimeStamp = 0;

        // 能够分入当前组的事件最大时间
        long groupEndTime = 0;
        long lastGroupEndTime = 0;
        long lastSendTime = 0;
        // 数据块的发送时间，如果触发的是10000条，则发送时间是当前事件时间，如果触发的是10s规则，发送时间=上次发送时间+10s
        long maxTimeStamp = 0;
        try (Scanner scanner = new Scanner(new FileReader("2022-07-25-13-46-55.out"))) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                if (i % 10000 == 0) {
                    System.out.println(i);
                }
                try {
                    Map<String, Object> jsonMap = JsonToMap.toMap(line);
                    EventRecord eventRecord = jsonMapToEventRecord(jsonMap);
                    addToBuilder(builder, eventRecord);

                    // 时间产生的时间
                    long eventTime = eventRecord.getTimestamp() / 1000000000;

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
                        dataBlock.data = Snappy.compress(builder.build().toByteArray());
                        dataBlock.dataSize = dataBlock.data.length;

                        list.add(dataBlock);

                        lastSendTime = lastSendTime == 0 ? eventTime : lastSendTime + 10;
                        //lastGroupEndTime = maxTimeStamp == groupEndTime ? groupEndTime : maxTimeStamp;
                        lastGroupEndTime = maxTimeStamp == groupEndTime ? groupEndTime : maxTimeStamp;
                        groupEndTime = 0;
                        groupCount = 0;
                        builder.clear();
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

                i++;
                groupCount++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        DataBlock dataBlock = new DataBlock();
        dataBlock.sendTime = maxTimeStamp - startUpTimeStamp;
        dataBlock.eventCount = groupCount;
        dataBlock.data = Snappy.compress(builder.build().toByteArray());
        dataBlock.dataSize = dataBlock.data.length;
        list.add(dataBlock);

        oos.writeObject(list);
        oos.flush();
        oos.close();
        System.out.println(list.stream().map(l -> l.eventCount).reduce((s1, s2) -> s1 + s2).get());
        System.out.println("over.");
    }

    public static void addToBuilder(Builder builer, EventRecord eventRecord) {
        builer.addProcessID(eventRecord.getProcessId());
        builer.addThreadID(eventRecord.getThreadId());
        builer.addTimestamp(eventRecord.getTimestamp());
        if (eventRecord.getCallstack() != null) {
            builer.addCallstack(ByteString.copyFromUtf8(eventRecord.getCallstack()));
        }
        EventTypeWaper waper = EventFormat.getEventTypeWaper(eventRecord.getEtwEventType());
        if (waper == null) {
            waper = new EventTypeWaper(3740466758L, 32);
        }
        builer.addProviderID(waper.ProviderId);
        builer.addOpcode(waper.OpCode);

        EventFormat.getArgNamesUsingEventType(eventRecord.getEtwEventType()).stream().forEach(e -> {
            magicshield.Etwdata.datad.Builder dataBuilder = Etwdata.datad.newBuilder();
            Object value = eventRecord.argument.get(e);
            if (value == null) {
                System.out.println(e);
                return;
            }
            if (value instanceof String) {
                dataBuilder.addS(ByteString.copyFromUtf8(value.toString()));
            } else {
                dataBuilder.addD(((BigInteger) value).longValue());
            }
            builer.addData(dataBuilder.build());
        });
    }

    public static EventRecord jsonMapToEventRecord(Map<String, Object> jsonMap) throws UnsupportedEncodingException {
        int processId = 0;
        int threadId = 0;
        long timestamp = 0L;
        EtwEventType etwEventType = null;
        callstackBuilder.delete(0, callstackBuilder.length());

        argument.clear();
        for (Map.Entry<String, Object> entry : jsonMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (key.equals("processID")) {
                processId = Integer.valueOf(((JsonPrimitive) value).getAsInt());
            } else if (key.equals("threadID")) {
                threadId = Integer.valueOf(((JsonPrimitive) value).getAsInt());
            } else if (key.equals("TimeStamp")) {
                timestamp = Long.valueOf(((JsonPrimitive) value).getAsLong());
            } else if (key.equals("EventName")) {
                etwEventType = EtwEventType.valueOf(((JsonPrimitive) value).getAsString());
            } else if (key.equals("CallStack")) {
                callstackBuilder.append(((JsonPrimitive) value).getAsString());
            } else if (key.equals("arguments")) {
                HashMap<String, Object> subObject = (HashMap) value;
                for (Map.Entry<String, Object> subEntry : subObject.entrySet()) {
                    if (subEntry.getValue() instanceof JsonElement) {
                        JsonElement jsonElement = (JsonElement) subEntry.getValue();
                        boolean isNumber = isNumeric(jsonElement.getAsString());
                        if (isNumber && jsonElement.getAsString().length() > 0) {
                            argument.put(subEntry.getKey(), new BigInteger(jsonElement.getAsString()));
                        } else {
                            argument.put(subEntry.getKey(), jsonElement.getAsString());
                        }
                    }
                }

            }

        }
        EventRecord eventRecord = new EventRecord(etwEventType, processId, threadId, timestamp);
        if (callstackBuilder.length() > 0) {
            eventRecord.setCallstack(callstackBuilder.toString());
        }
        for (Map.Entry<String, Object> entry : argument.entrySet()) {
            eventRecord.argument.put(entry.getKey(), entry.getValue());
        }

        return eventRecord;
    }

    public static boolean isNumeric(String str) {
        for (int i = str.length(); --i >= 0;) {
            if (!Character.isDigit(str.charAt(i))) {
                return false;
            }
        }
        return true;
    }
}
