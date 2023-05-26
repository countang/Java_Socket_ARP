package Processes;
import java.io.*;
import java.util.*;

public class FileOperation {
    public static void writeObject(String path, String Interface, String MAC){
        try {
            Map<String, Object> map = new HashMap<String, Object>();
            map.put(Interface, MAC);

            List<Map<String, Object>> list=new ArrayList<Map<String,Object>>();
            FileOutputStream outStream = new FileOutputStream(path, true);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outStream);

            objectOutputStream.writeObject(map);
            outStream.close();
            System.out.println("successful");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    //清空文件内容
    public static void clearFile(String path){
        try {
            FileWriter fileWriter = new FileWriter(path);
            fileWriter.write("");
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<HashMap<String, Object>> readObject(String path){
        FileInputStream freader;
        try {
            freader = new FileInputStream(path);
            FileOutputStream fos = null;
            HashMap<String,Object> map;
            List<HashMap<String, Object>> hashMapList = new ArrayList<HashMap<String, Object>>();
            ObjectInputStream objectInputStream = null;
            Object ois = objectInputStream.readObject();
            while(ois != null){
                map = (HashMap<String,Object>)ois;
                hashMapList.add(map);
                ois = objectInputStream.readObject();
            }
            return hashMapList;
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    public static void main(String[] args) {
        FileOperation fileTest = new FileOperation();
        System.out.println(fileTest.readObject("src/Processes/Mtable.txt"));
    }
}
