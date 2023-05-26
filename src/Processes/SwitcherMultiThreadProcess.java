package Processes;
import java.io.*;
import java.net.Socket;
import java.util.*;

import static Processes.AppendKeyValuePairToFile.appendKeyValuePairToFile;
import static Processes.AppendKeyValuePairToFile.readHashMapFromFile;
import static Processes.Host.MacToByte;
import static Processes.Host.byteToMac;
import static Processes.Table.Sym_IP_Table;

public class SwitcherMultiThreadProcess extends Thread{
    private final Socket socket;
    private List<Socket> listSockets = new ArrayList<>();
    private static final int bufferSize = 8092;
    private static HashMap<String, Socket>Interface_Socket = new HashMap<>();


    public SwitcherMultiThreadProcess(Socket socket, List<Socket> listSockets){
        this.listSockets = listSockets;
        this.socket = socket;
    }

    public void BroadCast(Socket socket_now, byte[] by, int res)
    {
        // 将服务器接收到的消息发送给除了发送方以外的其他客户端
        for (Socket socket: listSockets)
        {
            if (socket != socket_now)  // 判断不是当前发送的客户端
            {
                BufferedOutputStream ps = null;
                try {
                    ps = new BufferedOutputStream(socket.getOutputStream());
                    ps.write(by, 0, res);   // 写入输出流，将内容发送给客户端的输入流
                    ps.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void TransitTo(Socket socket_sender, byte[] by, int res)
    {
        BufferedOutputStream ps = null;
        try {
            ps = new BufferedOutputStream(socket_sender.getOutputStream());
            ps.write(by, 0, res);   // 写入输出流，将内容发送给客户端的输入流
            ps.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //change the byte array to IP address
    public static String byteArrayToIp(byte[] bs) {
        StringBuilder sb = new StringBuilder();
        for (int i=0 ; i < bs.length; i++) {
            if(i != bs.length - 1){
                sb.append(bs[i] & 0xff).append(".");
            }else{
                sb.append(bs[i] & 0xff);
            }
        }
        return sb.toString();
    }

    public static int byte2ToInt(byte[] bytes, int off) {
        int b0 = bytes[off] & 0xFF;
        int b1 = bytes[off + 1] & 0xFF;
        return (b0 << 8) | b1;
    }

    public char GetIP_Sym(String IP_Str){
        char sym = 0;
        for(char getKey: Sym_IP_Table.keySet()){
            if(Sym_IP_Table.get(getKey).equals(IP_Str)){
                sym = getKey;
            }
        }
        return sym;
    }

    public String Get_Mac_Interface(String Interface, char Switcher_Sym){
        if(Switcher_Sym == 'M'){
            return readHashMapFromFile("src/Processes/MTable.ser").get(Interface);
        }
        else {
            return readHashMapFromFile("src/Processes/NTable.ser").get(Interface);
        }
    }

    @Override
    public void run(){
        BufferedInputStream ois = null;
        BufferedOutputStream oos = null;
        try {
            ois = new BufferedInputStream(socket.getInputStream());
            oos = new BufferedOutputStream(socket.getOutputStream());
            while(true){
                byte[] by = new byte[bufferSize];
                int res = 0;
                res = ois.read(by);
                if(by[0] == by[1] && by[1] == by[2] && by[2] == by[3] && by[0] == 0)
                    by[0] = 4;
                byte Frame_Type = by[0];
                if(Frame_Type == 0){
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

                    //动态更新数据报发送过程中的源MAC地址和目的MAC地址
                    String byte_src_mac_1 = Integer.toHexString(0xFF & Src_Mac[0]);
                    String byte_dest_mac_1 = Integer.toHexString(0xFF & Dest_Mac[0]);
                    int src_mac_1 = Integer.parseInt(byte_src_mac_1);
                    int dest_mac_1 = Integer.parseInt(byte_dest_mac_1);
                    String Interface = null;
                    char Switcher_sym = 0;
                    if((src_mac_1 == 20 && dest_mac_1 == 19)){
                        Switcher_sym = 'N';
                        char dest_sym = GetIP_Sym(Dest_IP_str);
                        if(dest_sym == 'D'){
                            Interface = "E0";
                        }
                        else if(dest_sym == 'F'){
                            Interface = "E1";
                        }
                        String new_src_mac = Get_Mac_Interface(Interface, Switcher_sym);
                        byte[] new_src_mac_byte = MacToByte(new_src_mac);
                        for(int j = 1; j < 7; j++){
                            by[j + 6] = by[j];
                            by[j] = new_src_mac_byte[j - 1];
                        }
                    }
                    else if(src_mac_1 == 18 && dest_mac_1 == 17){
                        Switcher_sym = 'M';
                        char dest_sym = GetIP_Sym(Dest_IP_str);
                        if(dest_sym == 'A'){
                            Interface = "E0";
                        }
                        else if(dest_sym == 'B'){
                            Interface = "E1";
                        }
                        else if(dest_sym == 'C'){
                            Interface = "E2";
                        }
                        String new_src_mac = Get_Mac_Interface(Interface, Switcher_sym);
                        byte[] new_src_mac_byte = MacToByte(new_src_mac);
                        for(int j = 1; j < 7; j++){
                            by[j + 6] = by[j];
                            by[j] = new_src_mac_byte[j - 1];
                        }
                    }

                    //将数据报文直接传给目的主机
                    else if(src_mac_1 == 11 || src_mac_1 == 12 || src_mac_1 == 13){
                        Switcher_sym = 'M';
                        for(String getKey: readHashMapFromFile("src/Processes/MTable.ser").keySet()){
                            if(Objects.equals(readHashMapFromFile("src/Processes/MTable.ser").get(getKey), Dest_Mac_str)){
                                Interface = getKey;
                            }
                        }
                    }
                    else if(src_mac_1 == 14 || src_mac_1 == 16){
                        Switcher_sym = 'N';
                        for(String getKey: readHashMapFromFile("src/Processes/NTable.ser").keySet()){
                            if(Objects.equals(readHashMapFromFile("src/Processes/NTable.ser").get(getKey), Dest_Mac_str)){
                                Interface = getKey;
                            }
                        }
                    }
                    System.out.println("获取到报文类型为：数据报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "，\n数据长度为" + Data_length_int + "，数据为" + Data_str + "\n");
                    Socket Sender_Socket = Interface_Socket.get(Interface);
                    System.out.println("向 " + Interface + " 接口转发数据报文");

                    TransitTo(Sender_Socket, by, res);
                }
                else if (Frame_Type == 1) {
                    byte[] Dest_Mac = Arrays.copyOfRange(by, 1, 7);
                    byte[] Src_Mac = Arrays.copyOfRange(by, 7, 13);
                    byte[] Dest_IP = Arrays.copyOfRange(by, 13, 17);
                    byte[] Src_IP = Arrays.copyOfRange(by, 17, 21);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
                    System.out.println("获取到报文类型为：ARP报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "\n");
                    BroadCast(socket, by, res);
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
                    System.out.println("获取到报文类型为：ARP响应报文。");
                    System.out.println("目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "\n");
                    BroadCast(socket, by, res);
                }
                else if(Frame_Type == 3)
                {
                    byte[] byte_Interface = Arrays.copyOfRange(by, 1, 3);
                    byte[] byte_mac = Arrays.copyOfRange(by, 3, 9);
                    String Interface_sym = new String(byte_Interface);
//                    String ip_str = byteArrayToIp(byte_ip);
                    String mac_str = byteToMac(byte_mac);
                    Interface_Socket.put(Interface_sym, socket);
//                    System.out.println(Interface_Socket);
                    System.out.println("获取到报文类型为：握手报文，交换机端口"+ Interface_sym + "握手成功！");
                    System.out.println("获取到MAC地址为" + mac_str + "\n");
                    if(Switcher.Switcher_Sym == 'M') {
                        appendKeyValuePairToFile(Interface_sym, mac_str, "src/Processes/MTable.ser");
                    }
                    else if(Switcher.Switcher_Sym == 'N'){
                        appendKeyValuePairToFile(Interface_sym, mac_str, "src/Processes/NTable.ser");
                    }
//                    BroadCast(socket, by, res);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
