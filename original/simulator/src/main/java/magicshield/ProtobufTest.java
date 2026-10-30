package magicshield;

import java.io.IOException;

import com.google.protobuf.ByteString;

import org.xerial.snappy.Snappy;

import magicshield.Etwdata.EventRecords;
import magicshield.Etwdata.EventRecords.Builder;

/**
 * ProtobufTest
 */
public class ProtobufTest {

    public static void main(String[] args) throws IOException {
        Builder builder = EventRecords.newBuilder();

        magicshield.Etwdata.datad.Builder dataBuilder = Etwdata.datad.newBuilder();
        dataBuilder.addS(ByteString.copyFromUtf8("fdsafd"));

        builder.addProcessID(1).addThreadID(1).addTimestamp(1L).addData(0, dataBuilder.build()).addProcessID(2)
                .addThreadID(2).addTimestamp(2L).addData(1, dataBuilder.build());

        EventRecords eventRecords = builder.build();
        int p = eventRecords.getProcessID(0);
        int t = eventRecords.getThreadID(0);
        builder.clear();
        eventRecords = builder.build();
        p = eventRecords.getProcessID(0);
        t = eventRecords.getThreadID(0);

        byte[] bytes = Snappy.compress(eventRecords.toByteArray());
        byte[] uncompressBytes = Snappy.uncompress(bytes);
        EventRecords eventRecords2 = EventRecords.parseFrom(uncompressBytes);
        int processId = eventRecords2.getProcessID(0);
        int threadId = eventRecords2.getThreadID(0);
        long timestamp = eventRecords2.getTimestamp(0);
        Etwdata.datad data = eventRecords.getData(0);
        System.out.println(data.getS(0));

        int processId2 = eventRecords2.getProcessID(0);
        int threadId2 = eventRecords2.getThreadID(0);
        long timestamp2 = eventRecords2.getTimestamp(0);
        Etwdata.datad data2 = eventRecords.getData(0);
        System.out.println(data2.getS(0));
    }
}