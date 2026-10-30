package magicshield;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import org.xerial.snappy.Snappy;

/**
 * WriteData
 */
public class WriteData {

    public static void main(String[] args) throws IOException {
        String text = "fdsjafjdafjdsafjda";
        List<DataBlock> list = new ArrayList<>();

        DataBlock dataBlock = new DataBlock();
        dataBlock.sendTime = 1;
        dataBlock.eventCount = 1;
        dataBlock.dataSize = 1;
        dataBlock.data = Snappy.compress(text);

        for (int i = 0; i < 10; i++) {
            list.add(dataBlock);
        }

        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("datablock.data"));
        oos.writeObject(list);
        oos.close();
        
    }
}