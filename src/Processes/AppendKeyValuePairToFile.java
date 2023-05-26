package Processes;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

import java.io.*;
import java.util.*;

public class AppendKeyValuePairToFile {
    public static void main(String[] args) {
        String fileName = "src/Processes/map.ser";
        // 添加新的键值对
        appendKeyValuePairToFile("key3", "value4", fileName);
        appendKeyValuePairToFile("key5", "value5", fileName);

        // 读取HashMap
        HashMap<String, String> map = readHashMapFromFile("src/Processes/map.ser");
        System.out.println(map);
    }

    public static void appendKeyValuePairToFile(String key, String value, String fileName) {
        HashMap<String, String> map = readHashMapFromFile(fileName);
        map.put(key, value);
        writeHashMapToFile(map, fileName);
//        System.out.println("New key-value pair added to file.");
    }

    public static HashMap<String, String> readHashMapFromFile(String fileName) {
        HashMap<String, String> map = new HashMap<>();
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName))) {
            map = (HashMap<String, String>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
//            System.out.println("Error reading HashMap from file: " + e.getMessage());
        }
        return map;
    }

    public static void writeHashMapToFile(HashMap<String, String> map, String fileName) {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName))) {
            oos.writeObject(map);
        } catch (IOException e) {
            System.out.println("Error writing HashMap to file: " + e.getMessage());
        }
    }
}
