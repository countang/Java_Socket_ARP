package Processes;
import java.io.*;
import java.net.Socket;
import java.util.*;

import static Processes.AppendKeyValuePairToFile.readHashMapFromFile;
import static Processes.Host.*;
import static Processes.Router.Interface_E0_IP;
import static Processes.Router.Router_Sym;
import static Processes.SwitcherMultiThreadProcess.byte2ToInt;
import static Processes.SwitcherMultiThreadProcess.byteArrayToIp;
import static Processes.Table.Sym_IP_Table;

public class RouterReadPipe extends Thread {
    private static Socket socket_EX;
    private static Socket socket_Between;
    private static PipedInputStream input;
    private static final int bufferSize = 8092;
    private static PipedOutputStream output;

    public RouterReadPipe(Socket socket_ex, Socket socket_between, PipedInputStream input1 , PipedOutputStream output1) {
        socket_EX = socket_ex;
        socket_Between = socket_between;
        input = input1;
        output = output1;
    }

    public void Transit_Server(Socket socket, byte[] by, int res)
    {
        // 将服务器接收到的消息发送给除了发送方以外的其他客户端
        BufferedOutputStream ps = null;
        try {
            ps = new BufferedOutputStream(socket.getOutputStream());
            ps.write(by, 0, res);   // 写入输出流，将内容发送给客户端的输入流
            ps.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public char GetSrcIP_Sym(String Source_IP_Str){
        char sym = 0;
        for(char getKey: Sym_IP_Table.keySet()){
            if(Sym_IP_Table.get(getKey).equals(Source_IP_Str)){
                sym = getKey;
            }
        }
        return sym;
    }


    @Override
    public void run() {
        try {
            int i = 0;
            while(true){
                byte[] by = new byte[bufferSize];
                int res = 0;
                res = input.read(by);
                if(by[0] == by[1] && by[1] == by[2] && by[2] == by[3] && by[0] == 0)
                    by[0] = 4;
                byte Frame_Type = by[0];
                String Mac_I_E0 = "17-10-22-ED-87-78";
                String Mac_I_E1 = "18-10-22-ED-87-78";
                String Mac_J_E0 = "19-10-22-ED-87-78";
                String Mac_J_E1 = "20-10-22-ED-87-78";
                byte[] byte_Mac_I_E0 = MacToByte(Mac_I_E0);
                byte[] byte_Mac_I_E1 = MacToByte(Mac_I_E1);
                byte[] byte_Mac_J_E0 = MacToByte(Mac_J_E0);
                byte[] byte_Mac_J_E1 = MacToByte(Mac_J_E1);
                if(Frame_Type == 0) {
                    byte[] Dest_Mac = Arrays.copyOfRange(by, 1, 7);
                    byte[] Src_Mac = Arrays.copyOfRange(by, 7, 13);
                    byte[] Dest_IP = Arrays.copyOfRange(by, 13, 17);
                    byte[] Src_IP = Arrays.copyOfRange(by, 17, 21);
                    byte[] Data_length = Arrays.copyOfRange(by, 21, 23);
                    int Data_length_int = byte2ToInt(Data_length, 0);
                    byte[] Data = Arrays.copyOfRange(by, 23, 23 + Data_length_int);
                    String Data_str = new String(Data);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
//                    System.out.println("获取到报文类型为：数据报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "，\n数据长度为" + Data_length_int + "，数据为" + Data_str);
                    char sym = GetSrcIP_Sym(Src_IP_str);
                    if (((sym == 'A' || sym == 'B' || sym == 'C') && Router_Sym == 'I') ||
                            ((sym == 'D' || sym == 'F') && Router_Sym == 'J')) {
                        int finalRes1 = res;
                        new Thread(() -> {
                            Transit_Server(socket_Between, by, finalRes1);
                        }).start();
                    } else {
                        char Dest_Sym = GetSrcIP_Sym(Dest_IP_str);
                        if (Dest_Sym == 'A' || Dest_Sym == 'B' || Dest_Sym == 'C') {
                            for (int j = 1; j < 7; j++) {
                                by[j + 6] = by[j];
                                by[j] = byte_Mac_I_E0[j - 1];
                                Src_Mac_str = Mac_I_E0;
                                Src_IP_str = Interface_E0_IP;
                            }
                        } else if (Dest_Sym == 'D' || Dest_Sym == 'F') {
                            for (int j = 1; j < 7; j++) {
                                by[j + 6] = by[j];
                                by[j] = byte_Mac_J_E0[j - 1];
                                Src_Mac_str = Mac_J_E0;
                                Src_IP_str = Interface_E0_IP;
                            }
                        }
                        String file_path;
                        System.out.println(Dest_IP_str);
                        if (Router_Sym == 'I') {
                            file_path = "src/Processes/I_ARP_Table.ser";
                        } else {
                            file_path = "src/Processes/J_ARP_Table.ser";
                        }
                        if (!readHashMapFromFile(file_path).containsKey(Dest_IP_str)) {
                            System.out.println("ARP高速缓存中没有下一跳地址，正在发送ARP请求报文...");
                            String finalSrc_Mac_str = Src_Mac_str;
                            String finalSrc_IP_str = Src_IP_str;
                            new Thread(() -> {
                                try {
                                    SendARPRequest(Dest_IP_str, socket_EX, finalSrc_IP_str, finalSrc_Mac_str);
                                } catch (IOException ex) {
                                    throw new RuntimeException(ex);
                                }
                            }).start();
                            boolean flag_MAC = false;
                            while (true) {
//                                System.out.println("Circle ARP高速缓存中的内容为：");
//                                for(String getKey: readHashMapFromFile(file_path).keySet()){
//                                    System.out.println(getKey + " : " + readHashMapFromFile(file_path).get(getKey));
//                                }
                                for (String getKey : readHashMapFromFile(file_path).keySet()) {
                                    if (getKey.equals(Dest_IP_str)) {
                                        flag_MAC = true;
                                        break;
                                    }
                                }
                                if (flag_MAC)
                                    break;
                                try {
                                    System.out.println("等待ARP响应报文...");
                                    Thread.sleep(1000);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        int finalRes = res;
                        System.out.println("正在转发数据报文...");
                        new Thread(() -> {
                            Transit_Server(socket_EX, by, finalRes);
                        }).start();
                        System.out.println("数据报文发送完毕。\n");
                    }
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void SendARPRequest(String Dest_IP, Socket socketEx, String Src_IP, String Src_Mac) throws IOException {
        byte[] byte_Dest_IP = ipToByteArray(Dest_IP);
        byte[] byte_Source_IP = ipToByteArray(Src_IP);
        String Dest_MAC = "00-00-00-00-00-00";
        byte[] byte_Dest_MAC = MacToByte(Dest_MAC);
        byte[] byte_Source_MAC = MacToByte(Src_Mac);

        OutputStream outputStream = socketEx.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        byte Frame_type = (byte) 1;
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(byte_Dest_MAC);
        dataOutputStream.write(byte_Source_MAC);
        dataOutputStream.write(byte_Dest_IP);
        dataOutputStream.write(byte_Source_IP);
        dataOutputStream.flush();
    }
}
