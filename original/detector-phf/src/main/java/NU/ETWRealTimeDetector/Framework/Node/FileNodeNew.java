package NU.ETWRealTimeDetector.Framework.Node;

import NU.ETWRealTimeDetector.Framework.Label.LabelType;
import bloomfilter.CanGenerateHashFrom;
import bloomfilter.mutable.BloomFilter;

import java.io.*;
import java.util.BitSet;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public class FileNodeNew extends Node {
    // cacheIndex
    int cacheIndex;
    // 文件路径的hashcode，用于快速计算cacheIndex，在cache中找到数据
    int filePathHashCode;
    // fileNode uuid 由当前对象的hashcode + filePATH 生成的UUID
    long uuid;
    String filePath;
    static final int cacheCount = 200;
    CacheItem[] cache = new CacheItem[cacheCount];
    StringBuilder builder = new StringBuilder();

    // 用于判断FileNode+LabelType 是否存在
    BloomFilter<byte[]> fileLabelFilter;

    // 用户判断FilePath是否存在
    BloomFilter<byte[]> filePathFilter;

    AtomicBoolean haveNewData = new AtomicBoolean(false);

    private static Map<String, FileNodeNew> clientId2instance = new HashMap<>();

    public static synchronized FileNodeNew getInstance(String clientId) {
        FileNodeNew instance = clientId2instance.get(clientId);
        if (instance == null) {
            instance = new FileNodeNew(clientId);
            clientId2instance.put(clientId, instance);
        }
        return instance;
    }

    public FileNodeNew(String clientId) {
        super(clientId);
        // load form disk
        File fileNodeLabelFile = new File("cacheData/" + clientId + "_fileNodeLabel");
        File fileNodeFile = new File("cacheData/" + clientId + "_fileNode");
        if (fileNodeLabelFile.exists()) {
            // load from disk
            try {
                fileLabelFilter = BloomFilter.readFrom(new FileInputStream(fileNodeLabelFile), CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                fileLabelFilter = BloomFilter.apply(5000000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
            }

        } else {
            fileLabelFilter = BloomFilter.apply(5000000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
        }

        if (fileNodeFile.exists()) {
            // load from disk
            try {
                filePathFilter = BloomFilter.readFrom(new FileInputStream(fileNodeFile), CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                filePathFilter = BloomFilter.apply(1000000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
            }

        } else {
            filePathFilter = BloomFilter.apply(1000000, 0.1, CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
        }
    }

    public void setFilePathFilter(byte[] files) {
        filePathFilter = BloomFilter.readFrom(new ByteArrayInputStream(files), CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
    }

    public void setFileLabelFilter(byte[] fileLabels) {
        fileLabelFilter = BloomFilter.readFrom(new ByteArrayInputStream(fileLabels), CanGenerateHashFrom.CanGenerateHashFromByteArray$.MODULE$);
    }

    public boolean isExist(String filePath) {
        int hashCode = filePath.hashCode();
        int index = (hashCode & Integer.MAX_VALUE) % cacheCount;
        CacheItem temp = cache[index];
        if (temp != null && temp.hashCode == hashCode) {
            return true;
        }
        return filePathFilter.mightContain(filePath.getBytes());
    }

    public boolean haveNewData() {
        return this.haveNewData.getAndSet(false);
    }

    public byte[] getFileLabelFilterBytes() {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        fileLabelFilter.writeTo(bOut);
        try {
            bOut.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return bOut.toByteArray();
    }

    public byte[] getFileNodeFilterBytes() {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        filePathFilter.writeTo(bOut);
        try {
            bOut.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return bOut.toByteArray();
    }

    public String getFilePath() {
        return this.filePath;
    }

    public void setFileName(String filePath) {
        // 当client重启时 会有相同的文件，当前版本每次client重启会清空file，所以生成file UUID是需要加上当前FileNodeNew对象的hashcode，否则两次生成的UUID相同，当AddFileNode事件发送到illustrator时，将会报错，FNode唯一约束
        this.filePath = filePath;
        byte[] filePathBytes = filePath.getBytes();
        filePathHashCode = filePath.hashCode();
        cacheIndex = (filePathHashCode & Integer.MAX_VALUE) % cacheCount;
        CacheItem temp = cache[cacheIndex];
        if (temp != null && temp.hashCode == filePathHashCode) {
            this.uuid = temp.uuid;
            this.labelList.clear();
            this.labelList.or(temp.labelList);
            return;
        }

        this.uuid = UUID.nameUUIDFromBytes((this.clientId + filePath).getBytes()).getLeastSignificantBits();
        //初始化labelList,清空,并从布隆过滤器中还原label
        labelList.clear();
        initLabel();

        filePathFilter.add(filePathBytes);
        if (!haveNewData.get()) {
            haveNewData.set(true);
        }

        // 当缓存为空时,初始化一个cacheItem
        if (temp == null) {
            cache[cacheIndex] = new CacheItem(filePathHashCode, this.uuid, labelList);
            return;
        }

        // 当缓存不为空时,重置cacheItem中的数据
        temp.hashCode = filePathHashCode;
        temp.uuid = uuid;

        // 缓存中没有找到,从布隆过滤器加载后,更新缓存
        temp.labelList.clear();
        temp.labelList.or(labelList);
    }

    @Override
    public void addLabel(LabelType labelType) {
        builder.delete(0, builder.length());
        builder.append(uuid);
        builder.append(labelType.ordinal());

        fileLabelFilter.add(builder.toString().getBytes());
        labelList.set(labelType.ordinal());
        CacheItem item = cache[cacheIndex];
        if (item != null && item.hashCode == filePathHashCode) {
            item.labelList.set(labelType.ordinal());
        }

        if (!haveNewData.get()) {
            haveNewData.set(true);
        }
    }

    private void initLabel() {
        if (!filePathFilter.mightContain(filePath.getBytes())) {
            return;
        }
        LabelType.fileLabels.forEach(label -> {

            builder.delete(0, builder.length());
            builder.append(uuid);
            builder.append(label.ordinal());

            boolean exist = fileLabelFilter.mightContain(builder.toString().getBytes());

            if (exist) {
                labelList.set(label.ordinal());
            }
        });
    }

    @Override
    public long getUuid() {
        return this.uuid;
    }

    static class CacheItem {
        Integer hashCode;
        Long uuid;
        BitSet labelList;

        public CacheItem(int hashCode, long uuid, BitSet labelList) {
            this.hashCode = hashCode;
            this.uuid = uuid;
            this.labelList = new BitSet();
            this.labelList.or(labelList);
        }
    }

    public void destory() {
        // todo 持久化
        fileLabelFilter.dispose();
        filePathFilter.dispose();
    }
}
