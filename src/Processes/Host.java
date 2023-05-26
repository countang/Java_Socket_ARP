package Processes;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

import static Processes.AppendKeyValuePairToFile.readHashMapFromFile;
import static Processes.SwitcherMultiThreadProcess.byte2ToInt;
import static Processes.SwitcherMultiThreadProcess.byteArrayToIp;
import static Processes.Table.Sym_IP_Table;
import static Processes.Table.Sym_Mac_Table;


public class Host extends Thread{
    public static char Host_Sym;
    private static String Switcher_Interface;
    private static String Host_IP;
    private static String Host_MAC;
    private static Socket Host_Socket;
    private static volatile String Data;
    private static volatile char Send_Sym;

    public static volatile HashMap<String, String> ARP_Table = new HashMap<>();
    private static volatile MyWindow myWindow;

    public Host(){
    }
    public Host(Socket socket){
        Host_Socket = socket;
    }

    public Host(String IP, String MAC, char Sym, String Interface){
        Host_IP = IP;
        Host_MAC = MAC;
        Host_Sym = Sym;
        Switcher_Interface = Interface;
    }

    //将IP地址转化为字节数组
    public static byte[] ipToByteArray(String ip) {
        String[] split = ip.split("\\.");
        byte[] bs = new byte[4];
        for (int i=0; i < split.length; i++) {
            bs[i] = (byte)Integer.parseInt(split[i]);
        }
        return bs;
    }

    /**
     * 将Mac地址字符串转换为byte数组
     * @param mac Mac地址字符串，格式如：78:44:fd:c9:87:a0
     * @return 该Mac地址的byte数组形式
     */
    static byte[] MacToByte(String mac) {
        byte[] macBytes = new byte[6];

        String[] strArr = mac.split("-");
        for (int i = 0; i < strArr.length; i++) {
            int value = Integer.parseInt(strArr[i], 16);
            macBytes[i] = (byte) value;
        }
        return macBytes;
    }
    /**
     * 将Mac地址的数组形式转换为字符串形式
     * @param macBytes mac地址的数组形式
     * @return Mac地址的字符串，格式如：78-44-fd-c9-87-a0
     */
    static String byteToMac(byte[] macBytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < macBytes.length; i++) {
            builder.append('-').append(Integer.toHexString(0xFF & macBytes[i]));
        }
        return builder.substring(1);
    }

    public static byte[] unsignedShortToByte2(int s) {
        byte[] targets = new byte[2];
        targets[0] = (byte) (s >> 8 & 0xFF);
        targets[1] = (byte) (s & 0xFF);
        return targets;
    }


    //开启子线程来接受发给主机的信息
    @Override
    public void run(){
        BufferedInputStream dataInputStream = null;
        try {
            dataInputStream = new BufferedInputStream(Host_Socket.getInputStream());
            while(true){
                byte[] by = new byte[1];
                dataInputStream.read(by);
                byte Frame_type = by[0];
                if(Frame_type == 0){
                    byte[] byte_before_data = new byte[22];
                    dataInputStream.read(byte_before_data);
                    byte[] Dest_Mac = Arrays.copyOfRange(byte_before_data, 0, 6);
                    byte[] Src_Mac = Arrays.copyOfRange(byte_before_data, 6, 12);
                    byte[] Dest_IP = Arrays.copyOfRange(byte_before_data, 12, 16);
                    byte[] Src_IP = Arrays.copyOfRange(byte_before_data, 16, 20);
                    byte[] Data_length = Arrays.copyOfRange(byte_before_data, 20, 22);
                    int Data_length_int = byte2ToInt(Data_length, 0);
                    byte[] data = new byte[Data_length_int];
                    dataInputStream.read(data);
                    String Data_str = new String(data);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
                    System.out.println("获取到报文类型为：数据报文，\n目的MAC地址为" + Dest_Mac_str + "，源MAC地址为" + Src_Mac_str + "，\n目的IP地址为" + Dest_IP_str + "，源IP地址为" + Src_IP_str + "，\n数据长度为" + Data_length_int + "，数据为" + Data_str + "\n");
                }
                else if (Frame_type == 1) {
//                    System.out.println("x获取到报文类型为：ARP请求报文");
//                    System.out.println("Host_IP:" + this.Host_IP);
                    byte[] ARPRequest = new byte[20];
                    dataInputStream.read(ARPRequest);
                    byte[] Dest_Mac = Arrays.copyOfRange(ARPRequest, 0, 6);
                    byte[] Src_Mac = Arrays.copyOfRange(ARPRequest, 6, 12);
                    byte[] Dest_IP = Arrays.copyOfRange(ARPRequest, 12, 16);
                    byte[] Src_IP = Arrays.copyOfRange(ARPRequest, 16, 20);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
//                    System.out.println("Dest_IP:" + Dest_IP_str);
                    if (Dest_IP_str.equals(Host_IP)) {
                        char sym_src = 0;
                        for (char getKey : Sym_IP_Table.keySet()) {
                            if (Sym_IP_Table.get(getKey).equals(Src_IP_str)) {
                                sym_src = getKey;
                            }
                        }
                        char sym_dest = 0;
                        for (char getKey : Sym_IP_Table.keySet()) {
                            if (Sym_IP_Table.get(getKey).equals(Dest_IP_str)) {
                                sym_dest = getKey;
                            }
                        }
                        Dest_Mac_str = Host_MAC;
                        System.out.println("收到来自" + Src_IP_str + "的ARP请求");
                        String IP_Next = Src_IP_str;
                        String Mac_Next = Src_Mac_str;
                        if (((sym_src == 'A' || sym_src == 'B' || sym_src == 'C') && (sym_dest == 'D' || sym_dest == 'F')) ||
                                ((sym_src == 'D' || sym_src == 'F') && (sym_dest == 'A' || sym_dest == 'B' || sym_dest == 'C'))) {
                            if (sym_src == 'A' || sym_src == 'B' || sym_src == 'C') {
                                IP_Next = "202.119.65.100";
                                Mac_Next = "19-10-22-ED-87-78";
                            } else if (sym_src == 'D' || sym_src == 'F') {
                                IP_Next = "202.119.64.100";
                                Mac_Next = "17-10-22-ED-87-78";
                            }
                        }

                        if(!ARP_Table.containsKey(Src_IP_str)){
                            myWindow.addData(IP_Next, Mac_Next);
                        }
                        System.out.println("发送ARP响应报文\n");
                        SendARPReply(Src_Mac_str, Host_MAC, Src_IP_str, Host_IP);
                    }
                }
                //收到ARP响应报文
                else if (Frame_type == 2)
                {
                    byte[] ARPReply = new byte[20];
                    dataInputStream.read(ARPReply);
                    byte[] Dest_Mac = Arrays.copyOfRange(ARPReply, 0, 6);
                    byte[] Src_Mac = Arrays.copyOfRange(ARPReply, 6, 12);
                    byte[] Dest_IP = Arrays.copyOfRange(ARPReply, 12, 16);
                    byte[] Src_IP = Arrays.copyOfRange(ARPReply, 16, 20);
                    String Dest_Mac_str = byteToMac(Dest_Mac);
                    String Src_Mac_str = byteToMac(Src_Mac);
                    String Dest_IP_str = byteArrayToIp(Dest_IP);
                    String Src_IP_str = byteArrayToIp(Src_IP);
                    if(Dest_IP_str.equals(Host_IP)){
                        char sym_src = 0;
                        for(char getKey: Sym_IP_Table.keySet()){
                            if(Sym_IP_Table.get(getKey).equals(Src_IP_str)){
                                sym_src = getKey;
                            }
                        }
                        char sym_dest = 0;
                        for(char getKey: Sym_IP_Table.keySet()){
                            if(Sym_IP_Table.get(getKey).equals(Dest_IP_str)){
                                sym_dest = getKey;
                            }
                        }
                        String IP_Next = Src_IP_str;
                        String Mac_Next = Src_Mac_str;
                        if(((sym_src == 'A' || sym_src == 'B' || sym_src == 'C') && (sym_dest == 'D' || sym_dest == 'F' )) ||
                                ((sym_src == 'D' || sym_src == 'F') && (sym_dest == 'A' || sym_dest == 'B' || sym_dest == 'C')))
                        {
                            if(sym_src == 'A' || sym_src == 'B' || sym_src == 'C'){
                                IP_Next = "202.119.65.100";
                                Mac_Next = "19-10-22-ED-87-78";
                            }
                            else if(sym_src == 'D' || sym_src == 'F'){
                                IP_Next = "202.119.64.100";
                                Mac_Next = "17-10-22-ED-87-78";
                            }
                        }

                        myWindow.addData(IP_Next, Mac_Next);
////                        System.out.println("ARP表更新成功为");
//                        //输出ARP表
//                        for(String getKey: ARP_Table.keySet()){
//                            System.out.println(getKey + " " + ARP_Table.get(getKey));
//                        }
                        System.out.println("收到来自" + Src_IP_str + "的ARP应答\n");
                    }
                }
//                else if(Frame_type == 3){
//                    byte[] handShake = new byte[8];
//                    dataInputStream.read(handShake);
//                    byte[] byte_Interface = Arrays.copyOfRange(handShake, 0, 2);
//                    String Interface_sym = new String(byte_Interface);
//                    byte[] MAC = Arrays.copyOfRange(handShake, 2, 8);
//                    String mac_str = byteToMac(MAC);
//                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    //发送握手报文
    private void HandShake() throws IOException {
//        boolean isConnected = Host_Socket.isConnected();
//        System.out.println(isConnected);
        System.out.println("主机" + Host_Sym + "握手成功。");
        System.out.println("主机" + Host_Sym + "的IP地址为：" + Host_IP);
        System.out.println("主机" + Host_Sym + "的MAC地址为：" + Host_MAC + "\n");
        OutputStream outputStream = Host_Socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        BufferedReader reader = new BufferedReader(new InputStreamReader(Host_Socket.getInputStream()));
        byte Frame_type = (byte)3;
        byte[] Interface = Switcher_Interface.getBytes();
        byte[] MAC = MacToByte(Host_MAC);
//        byte[]  byteIP = ipToByteArray(Host_IP);
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(Interface);
        dataOutputStream.write(MAC);
//        dataOutputStream.write(byteIP);
        dataOutputStream.flush();
    }

    private void SendDataGram() throws IOException {
//        Scanner scan = new Scanner(System.in);
        Data = null;
//        System.out.println("请输入要发送的数据信息：");
        while(Data == null){
        }
        Send_Sym = 0;
        while(Send_Sym == 0){
        }
        byte[] byte_data = Data.getBytes();
        int data_length = byte_data.length;
        byte[] byte_data_length = unsignedShortToByte2(data_length);

        String Dest_IP = Sym_IP_Table.get(Send_Sym);
        byte[] byte_Dest_IP = ipToByteArray(Dest_IP);
        byte[] byte_Source_IP = ipToByteArray(Host_IP);
        String Dest_MAC;
        byte[] byte_Dest_MAC = null;
        String Dest_Router_IP = null;
        boolean Cross_Router = false;
        if(((Host_Sym == 'A' || Host_Sym == 'B' || Host_Sym == 'C') && (Send_Sym == 'D' || Send_Sym == 'F')) ||
                ((Host_Sym == 'D' || Host_Sym == 'F') && (Send_Sym == 'A' || Send_Sym == 'B' || Send_Sym == 'C'))) {
            if (Host_Sym == 'A' || Host_Sym == 'B' || Host_Sym == 'C')
            {
                Dest_Router_IP = "202.119.64.100";
                Cross_Router = true;
            }
            else{
                Dest_Router_IP = "202.119.65.100";
                Cross_Router = true;
            }
        }

        while(true){
            boolean flag_MAC = false;
            for(String getKey: ARP_Table.keySet()){
                if(!Cross_Router){
                    if (getKey.equals(Dest_IP)) {
                        flag_MAC = true;
                        break;
                    }
                }
                else {
                    if (getKey.equals(Dest_Router_IP)) {
                        flag_MAC = true;
                        break;
                    }
                }
            }
            if(flag_MAC){
                break;
            }
            System.out.println("ARP高速缓存中没有下一跳地址，正在发送ARP请求报文...");
            SendARPRequest(Host_Sym, Send_Sym);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }


        if(byte_Dest_IP[2] == byte_Source_IP[2]){
            System.out.println("目的主机在同一网络中...");
            String Interface_str = null;
            switch (Send_Sym){
                case 'D':
                case 'A':
                    Interface_str = "E0";
                    break;
                case 'F':
                case 'B':
                    Interface_str = "E1";
                    break;
                case 'C':
                    Interface_str = "E2";
                    break;
            }
            if(Send_Sym == 'A' || Send_Sym == 'B' || Send_Sym == 'C'){
                Dest_MAC = readHashMapFromFile("src/Processes/MTable.ser").get(Interface_str);
            }
            else{
                Dest_MAC = readHashMapFromFile("src/Processes/NTable.ser").get(Interface_str);
            }
        }
        else{
            System.out.println("目的主机不在同一网络中...");
            if(Host_Sym == 'A' || Host_Sym == 'B' || Host_Sym == 'C'){
                Dest_MAC = "17-10-22-ED-87-78";
            }
            else{
                Dest_MAC = "19-10-22-ED-87-78";
            }
        }
        byte_Dest_MAC = MacToByte(Dest_MAC);

        OutputStream outputStream = Host_Socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
//        BufferedReader reader = new BufferedReader(new InputStreamReader(Host_Socket.getInputStream()));
        byte Frame_type = (byte)0;
        byte[] byte_Source_Mac = MacToByte(Host_MAC);
//        byte[]  byteIP = ipToByteArray(Host_IP);
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(byte_Dest_MAC);
        dataOutputStream.write(byte_Source_Mac);
        dataOutputStream.write(byte_Dest_IP);
        dataOutputStream.write(byte_Source_IP);
        dataOutputStream.write(byte_data_length);
        dataOutputStream.write(byte_data);
//        dataOutputStream.write(byteIP);
        dataOutputStream.flush();
//        System.out.println(ARP_Table.get(0).getFirst());
        System.out.println("数据发送成功。\n");
    }

    private void SendARPRequest(char source_sym, char dest_sym) throws IOException {
        if (((source_sym == 'A' || source_sym == 'B' || source_sym == 'C') && (dest_sym == 'D' || dest_sym == 'F')) ||
                ((source_sym == 'D' || source_sym == 'F') && (dest_sym == 'A' || dest_sym == 'B' || dest_sym == 'C')))
        {
            System.out.println("ARP请求对象不在同一个网络中，将ARP请求发送给路由器...");
            String Dest_MAC = "00-00-00-00-00-00";
            byte[] byte_Dest_MAC = MacToByte(Dest_MAC);
            String Source_MAC = Host_MAC;
            byte[] byte_Source_MAC = MacToByte(Source_MAC);
            String Dest_IP;
            if(source_sym == 'A' || source_sym == 'B' || source_sym == 'C'){
                Dest_IP = "202.119.64.100";  //路由器M的E0端口IP
            }
            else{
                Dest_IP = "202.119.65.100";  //路由器N的E0端口IP
            }


            byte[] byte_Dest_IP = ipToByteArray(Dest_IP);
            byte[] byte_Source_IP = ipToByteArray(Host_IP);

            OutputStream outputStream = Host_Socket.getOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            byte Frame_type = (byte) 1;
            dataOutputStream.write(Frame_type);
            dataOutputStream.write(byte_Dest_MAC);
            dataOutputStream.write(byte_Source_MAC);
            dataOutputStream.write(byte_Dest_IP);
            dataOutputStream.write(byte_Source_IP);
            dataOutputStream.flush();
        }
        else {
            System.out.println("ARP请求对象在同一个网络中...");
            String Dest_MAC = "00-00-00-00-00-00";
            byte[] byte_Dest_MAC = MacToByte(Dest_MAC);
            String Source_MAC = Host_MAC;
            byte[] byte_Source_MAC = MacToByte(Source_MAC);
            String Dest_IP = Sym_IP_Table.get(dest_sym);
            byte[] byte_Dest_IP = ipToByteArray(Dest_IP);
            byte[] byte_Source_IP = ipToByteArray(Host_IP);

            OutputStream outputStream = Host_Socket.getOutputStream();
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

    private void SendARPReply(String Dest_Mac_Str, String Src_Mac_Str, String Dest_IP_Str, String Src_IP_Str) throws IOException {
        System.out.println("本主机正在发送ARP应答报文...");
        byte[] byte_Dest_MAC = MacToByte(Dest_Mac_Str);
        byte[] byte_Source_MAC = MacToByte(Src_Mac_Str);
        byte[] byte_Dest_IP = ipToByteArray(Dest_IP_Str);
        byte[] byte_Source_IP = ipToByteArray(Src_IP_Str);
        OutputStream outputStream = Host_Socket.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        byte Frame_type = (byte) 2;
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(byte_Dest_MAC);
        dataOutputStream.write(byte_Source_MAC);
        dataOutputStream.write(byte_Dest_IP);
        dataOutputStream.write(byte_Source_IP);
        dataOutputStream.flush();
    }

    //init host
    private void SetHost() throws IOException {
//        System.out.println("请输入要建立连接的主机IP地址、MAC地址以及主机标识符：");
//        Scanner scan = new Scanner(System.in);
//        String ip = scan.nextLine();
//        String MAC = scan.nextLine();
        String Interface = null;
//        char sym = (char)System.in.read();
//        scan.nextLine();
        char sym = Host_Sym;
        switch (sym){
            case 'D':
            case 'A': Interface = "E0";
            break;
            case 'F':
            case 'B': Interface = "E1";
            break;
            case 'C': Interface = "E2";
            break;
        }
        Host_IP = Sym_IP_Table.get(sym);
        Host_MAC = Sym_Mac_Table.get(sym);
        Switcher_Interface = Interface;
    }

    public static class MyWindow extends JFrame {
        private boolean isRunning = true;
        private final JComboBox<String> comboBox;
        private final JTextArea textArea;
        private DefaultTableModel model;
        public void updateTableData() {
            model.setRowCount(0);
            for (String key : ARP_Table.keySet()) {
                model.addRow(new Object[]{key, ARP_Table.get(key)});
            }
            model.fireTableDataChanged();
        }
        public void addData(String key, String value) {
            ARP_Table.put(key, value);
            updateTableData();
        }

        // 删除哈希表中的数据并更新表格
        public void removeData(String key) {
            ARP_Table.remove(key);
            updateTableData();
        }



        public MyWindow(Host host) {
            myWindow = this;
            JFrame.setDefaultLookAndFeelDecorated(true);
            // 设置窗口属性
            setTitle("主机");
            setSize(600, 350);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            // 创建下拉框
            String[] options = {"A", "B", "C", "D", "F"};
            comboBox = new JComboBox<>(options);

            // 创建按钮
            JButton button = new JButton("启动主机");
            button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String option = (String) comboBox.getSelectedItem();
                    // 在文本框中显示结果
//                    textArea.append("Option selected: " + option + "\n");
                    Host_Sym = option.charAt(0);
                    new Thread(()->{
                        try {
                            System.out.println("主机" + Host_Sym + "开始运行...");
                            connect(host);
                        } catch (IOException ex) {
                            throw new RuntimeException(ex);
                        }
                    }).start();
                }
            });
            //创建一个文本输入框
            JTextField textField_Data = new JTextField(20);

            String[] Data_Send_Sym_options = {"A", "B", "C", "D", "F"};
            JComboBox<String> Data_Send_comboBox = new JComboBox<>(Data_Send_Sym_options);

            // 创建按钮
            JButton Send_Data_button = new JButton("Send Data");
            Send_Data_button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String option = (String) Data_Send_comboBox.getSelectedItem();
                    if(Objects.equals(option, comboBox.getSelectedItem())){
                        return;
                    }
                    String text = textField_Data.getText();
                    Data = text;
                    textField_Data.setText("");
                    // 在文本框中显示结果
                    Send_Sym = option.charAt(0);
                }
            });



            // 创建文本框
            textArea = new JTextArea(10, 30);
            textArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textArea);
            JLabel label_Choose_Host = new JLabel("         请选择要启动的主机：");
            JLabel label_Choose_Send_Host = new JLabel("目标主机：");
            JLabel label_Data = new JLabel("发送数据：");
            JLabel ARP_Label = new JLabel("ARP高速缓存表");

            model = new DefaultTableModel(new Object[]{"Key", "Value"}, 0);
            ARP_Table.put("   IP地址", "            MAC地址");

            // 将哈希表数据添加到表格模型中
            for (String key : ARP_Table.keySet()) {
                model.addRow(new Object[]{key, ARP_Table.get(key)});
            }
            JTable table = new JTable(model);
            TableColumnModel columnModel = table.getColumnModel();
            columnModel.getColumn(0).setPreferredWidth(110);
            columnModel.getColumn(1).setPreferredWidth(135);

            // 添加组件到窗口
            JPanel panel = new JPanel();
            panel.add(ARP_Label);
            panel.add(label_Choose_Host);
            panel.add(comboBox);
            panel.add(button);
            JPanel panel1 = new JPanel();
            JPanel panel2 = new JPanel();
            panel2.add(table);
            panel1.add(label_Choose_Send_Host);
            panel1.add(Data_Send_comboBox);
            panel1.add(label_Data);
            panel1.add(textField_Data);
            panel1.add(Send_Data_button);
            add(panel, BorderLayout.NORTH);
            add(panel2, BorderLayout.WEST);
            add(panel1, BorderLayout.AFTER_LAST_LINE);
            add(scrollPane, BorderLayout.CENTER);
            JTextAreaOutputStream out = new JTextAreaOutputStream(textArea);
            System.setOut(new PrintStream(out));//设置输出重定向

            // 显示窗口
            setVisible(true);
        }
    }
    //将输出流重定向到界面
    static class JTextAreaOutputStream extends OutputStream
    {
        private final JTextArea destination;
        public JTextAreaOutputStream (JTextArea destination)
        {
            if (destination == null)
                throw new IllegalArgumentException ("Destination is null");
            this.destination = destination;
        }
        @Override
        public void write(byte[] buffer, int offset, int length) throws IOException
        {
            final String text = new String (buffer, offset, length);
            SwingUtilities.invokeLater(new Runnable ()
            {
                @Override
                public void run()
                {
                    destination.append (text);
                }
            });
        }
        @Override
        public void write(int b) throws IOException
        {
            write (new byte [] {(byte)b}, 0, 1);
        }
    }

    public static void connect(Host host) throws IOException {
        if (Host_Sym == 'A' || Host_Sym == 'B' || Host_Sym == 'C') {
            Host_Socket = new Socket("localhost", 9998);
        } else {
            Host_Socket = new Socket("localhost", 9997);
        }
        host.SetHost();

        Host sonThread = new Host(Host_Socket);
        sonThread.start();
        host.HandShake();
        while (true) {
            host.SendDataGram();
        }
    }






    public static void main(String[] args) throws IOException {
        Host host = new Host();
        MyWindow window = new MyWindow(host);
    }
}