package claps.health.utils;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;

public class Utils {
    public static byte[] get_file_bytes(FileInputStream fileInputStream){
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            int numRead = 0;
            byte[] buf = new byte[1024];
            while ((numRead = fileInputStream.read(buf)) != -1) {
                os.write(buf, 0, numRead);
            }
            return os.toByteArray();
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] createDataInBytes(int msgSize, String patternStr) {
        char[] pattern = patternStr.toCharArray();
        byte[] result = new byte[msgSize];
        int patternLength = pattern.length;
        for (int i=0; i<msgSize; i++) {
            result[i] = (byte) pattern[i % patternLength];
        }
        return result;
    }
}
