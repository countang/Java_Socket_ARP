package Processes;
import java.io.*;
import java.net.Socket;
import java.util.*;

import static Processes.AppendKeyValuePairToFile.appendKeyValuePairToFile;
import static Processes.AppendKeyValuePairToFile.readHashMapFromFile;
import static Processes.Host.MacToByte;
import static Processes.Host.byteToMac;
import static Processes.Router.*;
import static Processes.SwitcherMultiThreadProcess.byte2ToInt;
import static Processes.SwitcherMultiThreadProcess.byteArrayToIp;
import static Processes.Table.Sym_IP_Table;

public class RouterReadServer extends Thread {
    private static Socket socket;
    private static Socket socket_EX;
    private static Socket socket_Between;
    private static final int bufferSize = 8092;
    private static PipedInputStream input;
    private static PipedOutputStream output;
    private int Flag;
    private String IP_Str;
    private String Mac_Str;

    public RouterReadServer(Socket socket_ex, Socket socket_between ,  PipedInputStream input1 , PipedOutputStream output1, int flag) {
        socket_EX = socket_ex;
        socket_Between = socket_between;
        input = input1;
        output = output1;
        Flag = flag;
        if(Router_Sym == 'I' && Flag == 1){
            IP_Str = Interface_E0_IP;
            Mac_Str = Interface_E0_MAC;
        }
        else if(Router_Sym == 'I' && Flag == 2){
            IP_Str = Interface_E1_IP;
            Mac_Str = Interface_E1_MAC;
        }
        else if(Router_Sym == 'J' && Flag == 1){
            IP_Str = Interface_E0_IP;
            Mac_Str = Interface_E0_MAC;
        }
        else if(Router_Sym == 'J' && Flag == 2){
            IP_Str = Interface_E1_IP;
            Mac_Str = Interface_E1_MAC;
        }
    }

    public void Transit_Pipe(byte[] by, int res)
    {
        // 将服务器接收到的消息发送给除了发送方以外的其他客户端
        try {
            output.write(by, 0, res);   // 写入输出流，将内容发送给客户端的输入流
            output.flush();
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

    private void SendARPReply(String Dest_Mac_Str, String Src_Mac_Str, String Dest_IP_Str, String Src_IP_Str) throws IOException {
        byte[] byte_Dest_MAC = MacToByte(Dest_Mac_Str);
        byte[] byte_Source_MAC = MacToByte(Src_Mac_Str);
        byte[] byte_Dest_IP = ipToByteArray(Dest_IP_Str);
        byte[] byte_Source_IP = ipToByteArray(Src_IP_Str);

        OutputStream outputStream = socket_EX.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        byte Frame_type = (byte) 2;
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(byte_Dest_MAC);
        dataOutputStream.write(byte_Source_MAC);
        dataOutputStream.write(byte_Dest_IP);
        dataOutputStream.write(byte_Source_IP);
        dataOutputStream.flush();
    }

    @Override
    public void run() {
//        System.out.println(Mac_Str);
        BufferedInputStream ois = null;
        BufferedOutputStream oos = null;
        if(Flag == 1)
            socket = socket_EX;
        else
            socket = socket_Between;
        try {
                ois = new BufferedInputStream(socket.getInputStream());
                oos = new BufferedOutputStream(socket.getOutputStream());
            int i = 0;
            while(true){
                byte[] by = new byte[bufferSize];
                int res = 0;
                res = ois.read(by);
                if(by[0] == by[1] && by[1] == by[2] && by[2] == by[3] && by[0] == 0)
                    by[0] = 4;
                byte Frame_Type = by[0];
                if(Frame_Type == 0){
                    String Mac_I_E0 = "17-10-22-ED-87-78";
                    String Mac_I_E1 = "18-10-22-ED-87-78";
                    String Mac_J_E0 = "19-10-22-ED-87-78";
                    String Mac_J_E1 = "20-10-22-ED-87-78";
                    byte[] byte_Mac_I_E0 = MacToByte(Mac_I_E0);
                    byte[] byte_Mac_I_E1 = MacToByte(Mac_I_E1);
                    byte[] byte_Mac_J_E0 = MacToByte(Mac_J_E0);
                    byte[] byte_Mac_J_E1 = MacToByte(Mac_J_E1);
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
                    System.out.println("获取到报文类型为：数据报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "，\n数据长度为" + Data_length_int + "，数据为" + Data_str + "\n");
                    if(Router_Sym == 'I'){
                        if(!readHashMapFromFile("src/Processes/I_ARP_Table.ser").containsKey(Interface_E1_IP)){
                            //将路由器J的E1端口信息添加到ARP高速缓存中
                            appendKeyValuePairToFile("202.119.66.101", "20-10-22-ED-87-78", "src/Processes/I_ARP_Table.ser");
                            myWindow.addData("202.119.66.101", "20-10-22-ED-87-78");
                        }
                    }
                    else{
                        if(!readHashMapFromFile("src/Processes/J_ARP_Table.ser").containsKey(Interface_E1_IP)){
                            //将路由器I的E1端口信息添加到ARP高速缓存中
                            appendKeyValuePairToFile("202.119.66.100", "18-10-22-ED-87-78", "src/Processes/J_ARP_Table.ser");
                            myWindow.addData("202.119.66.100", "18-10-22-ED-87-78");
                        }
                    }

                    char sym = GetSrcIP_Sym(Src_IP_str);
                    if(((Flag == 1) && (socket_EX.getPort() == 9998) && (sym == 'A' || sym == 'B' || sym == 'C'))){
                        for(int j = 1; j < 7; j++){
                            by[j + 6] = by[j];
                            by[j] = byte_Mac_I_E1[j - 1];
                        }
                    }
                    else if(((Flag == 1) && (socket_EX.getPort() == 9997) && (sym == 'D' || sym == 'F'))){
                        for(int j = 1; j < 7; j++){
                            by[j + 6] = by[j];
                            by[j] = byte_Mac_J_E1[j - 1];
                        }
                    }
                    else if(Flag == 2){
                        if(socket_EX.getPort() == 9998){
//                            System.out.println("9998");
                            for(int j = 1; j < 7; j++){
                                by[j + 6] = by[j];
                                by[j] = byte_Mac_I_E1[j - 1];
                            }
                        }
                        else{
//                            System.out.println("9997");
                            for(int j = 1; j < 7; j++){
                                by[j + 6] = by[j];
                                by[j] = byte_Mac_J_E1[j - 1];
                            }
                        }
                    }
                    Transit_Pipe(by, res);
                }

                else if (Frame_Type == 1) {
                    byte[] Dest_Mac = Arrays.copyOfRange(by, 1, 7);
                    byte[] Src_Mac = Arrays.copyOfRange(by, 7, 13);
                    byte[] Dest_IP = Arrays.copyOfRange(by, 13, 17);
                    byte[] Src_IP = Arrays.copyOfRange(by, 17, 21);
//                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
                    String Dest_Mac_str = Interface_E0_MAC;
                    if(Dest_IP_str.equals(Interface_E0_IP)){
                        System.out.println("获取到报文类型为：ARP请求报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "\n");
                        if(Router_Sym == 'I'){
                            if(!readHashMapFromFile("src/Processes/I_ARP_Table.ser").containsKey(Src_IP_str)){
                                appendKeyValuePairToFile(Src_IP_str, Src_Mac_str, "src/Processes/I_ARP_Table.ser");
                                myWindow.addData(Src_IP_str, Src_Mac_str);
                            }
                        }
                        else{
                            if(!readHashMapFromFile("src/Processes/J_ARP_Table.ser").containsKey(Src_IP_str)){
                                appendKeyValuePairToFile(Src_IP_str, Src_Mac_str, "src/Processes/J_ARP_Table.ser");
                                myWindow.addData(Src_IP_str, Src_Mac_str);
                            }
                        }
                        new Thread(()->{
                            try {
                                SendARPReply(Src_Mac_str, Dest_Mac_str, Src_IP_str, Dest_IP_str);
                            } catch (IOException ex) {
                                throw new RuntimeException(ex);
                            }
                        }).start();
                    }

                }
                else if (Frame_Type == 2)
                {
                    byte[] Dest_Mac = Arrays.copyOfRange(by, 1, 7);
                    byte[] Src_Mac = Arrays.copyOfRange(by, 7, 13);
                    byte[] Dest_IP = Arrays.copyOfRange(by, 13, 17);
                    byte[] Src_IP = Arrays.copyOfRange(by, 17, 21);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
                    if(Dest_IP_str.equals(Interface_E0_IP)){
                        System.out.println("获取到报文类型为：ARP响应报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "\n");
                        if(Router_Sym == 'I'){
                            appendKeyValuePairToFile(Src_IP_str, Src_Mac_str, "src/Processes/I_ARP_Table.ser");
                            myWindow.addData(Src_IP_str, Src_Mac_str);

                        }
                        else{
                            appendKeyValuePairToFile(Src_IP_str, Src_Mac_str, "src/Processes/J_ARP_Table.ser");
                            myWindow.addData(Src_IP_str, Src_Mac_str);
                        }

                    }

                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
