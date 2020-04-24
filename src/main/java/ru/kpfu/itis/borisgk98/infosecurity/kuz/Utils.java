package ru.kpfu.itis.borisgk98.infosecurity.kuz;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Utils {

    private static final byte STOP_BYTE = (byte) 0x80;

    public static byte[] mergeArrays(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        for (int i = 0; i < a1.length; i++) {
            result[i] = a1[i];
        }
        for (int i = 0; i < a2.length; i++) {
            result[i + a1.length] = a2[i];
        }
        return result;
    }

    // TODO make parallel
    static public List<byte[]> split(byte[] data, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < data.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            for (int k = i; k < i + blockSize; k++) {
                if (k == data.length) {
                    block[k % blockSize] = STOP_BYTE;
                }
                else if (k > data.length) {
                    block[k % blockSize] = 0x0;
                }
                else {
                    block[k % blockSize] = data[k];
                }
            }
            blocks.add(block);
        }
        if (data.length % blockSize == 0) {
            byte[] block = new byte[blockSize];
            block[0] = STOP_BYTE;
            for (int k = 1; k < blockSize; k++) {
                block[k] = 0x0;
            }
            blocks.add(block);
        }
        return blocks;
    }

    // TODO make parallel
    static public List<byte[]> split2(byte[] data, int blockSize) {
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException();
        }
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < data.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            for (int k = i; k < i + blockSize; k++) {
                block[k % blockSize] = data[k];
            }
            blocks.add(block);
        }
        return blocks;
    }

    // TODO make parallel
    static public byte[] unsplit(List<byte[]> data) {
        ArrayList<Byte> result = new ArrayList<>();
        for (int i = 0; i < data.size() - 1; i++) {
            for (int j = 0; j < data.get(i).length; j++) {
                result.add(data.get(i)[j]);
            }
        }
        byte[] lastBlock = data.get(data.size() - 1);
        int k = lastBlock.length - 1;
        while (k >= 0 && lastBlock[k] != STOP_BYTE) {
            k--;
        }
        if (k < 0) {
            throw new IllegalArgumentException();
        }
        for (int i = 0; i < k; i++) {
            result.add(lastBlock[i]);
        }
        return convert(result);
    }

    public static byte[] convert(List<Byte> list) {
        byte[] result = new byte[list.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = list.get(i);
        }
        return result;
    }

    public static byte[] convert2(List<byte[]> list) {
        return list.stream().reduce(Utils::mergeArrays).orElse(new byte[]{});
    }

    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException();
        }
        byte[] result = Arrays.copyOf(a, a.length);
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
