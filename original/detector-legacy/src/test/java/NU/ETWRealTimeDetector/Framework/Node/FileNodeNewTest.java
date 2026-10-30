package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import NU.ETWRealTimeDetector.Util.MD5;
import bloomfilter.CanGenerateHashFrom;
import bloomfilter.mutable.BloomFilter;
import org.junit.Test;

import java.util.BitSet;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertTrue;

public class FileNodeNewTest {

    static BloomFilter<byte[]> bf = BloomFilter.apply(10_0000_0000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);

    @Test
    public void testBitSet() {
        BitSet labels = new BitSet(LabelType.getSize());
        BitSet labelsTemp = new BitSet(LabelType.getSize());

        labels.set(LabelType.FT1.ordinal());
        labelsTemp.set(LabelType.FT2.ordinal());

        Set<LabelType> set = getLabels(labels);

        labelsTemp.clear();
        labelsTemp.or(labels);
        Set<LabelType> setTemp = getLabels(labelsTemp);
        assertTrue(set.containsAll(setTemp));
    }

    private Set<LabelType> getLabels(BitSet labelList) {
        Set<LabelType> result = new HashSet<>();
        for (int i = 0; i < labelList.length(); i++) {
            if (labelList.get(i)) {
                result.add(LabelType.getLabelType(i));
            }
        }
        return result;
    }

    @Test
    public void testBF() {

        BloomFilter<byte[]> fileLabelFilter = BloomFilter.apply(1000000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
    }

    @Test
    public void setFileName() {


        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000000; i++) {
            UUID.nameUUIDFromBytes(String.valueOf(i).getBytes());
        }
        long end = System.currentTimeMillis();
        long time = end - start;
        System.out.println("1000W UUID:" + time);

        start = System.currentTimeMillis();
        for (int i = 0; i < 10000000; i++) {
            bf.mightContain(String.valueOf(i).getBytes());
        }
        end = System.currentTimeMillis();
        time = end - start;
        System.out.println("1000W bf:" + time);

        start = System.currentTimeMillis();
        for (int i = 0; i < 1000000; i++) {
            MD5.hashKeyForDisk(String.valueOf(i));
        }
        end = System.currentTimeMillis();
        time = end - start;
        System.out.println("100W MD5:" + time);

        FileNodeNew fileNodeNew = new FileNodeNew("test");
        String filePath = "sdfsafdsafdsafdasfdasfdarewrewrewrewrewrewrewrewrew";
        StringBuilder builder = new StringBuilder();
        start = System.currentTimeMillis();
        for (int i = 0; i < 10000000; i++) {
            builder.delete(0, builder.length());
            builder.append(filePath);
            builder.append(i);
            fileNodeNew.setFileName(builder.toString());
            fileNodeNew.setFileName(builder.toString());
        }
        end = System.currentTimeMillis();
        time = end - start;
        System.out.println("1000W FileNodeNew:" + time);
    }
}