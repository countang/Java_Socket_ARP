package Processes;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.util.*;
import java.util.List;

import static Processes.AppendKeyValuePairToFile.readHashMapFromFile;
import static Processes.FileOperation.clearFile;
import static Processes.Host.MacToByte;

public class Router extends Thread{
    public volatile static char Router_Sym;
    private static String Switcher_Interface;
    public volatile static String Interface_E0_IP;
    public volatile static String Interface_E1_IP;
    private volatile static Socket Socket_Ex;
    public volatile static String Interface_E0_MAC;
    public volatile static String Interface_E1_MAC;
    public static volatile MyWindow myWindow;



    public static byte[] ipToByteArray(String ip) {
        String[] split = ip.split("\\.");
        byte[] bs = new byte[4];
        for (int i=0; i < split.length; i++) {
            bs[i] = (byte)Integer.parseInt(split[i]);
        }
        return bs;
    }
    public Router(){
    }

    private void SetRouter() throws IOException {
        if(Router_Sym == 'I'){
            Switcher_Interface = "E3";
            Interface_E0_IP = "202.119.64.100";
            Interface_E1_IP = "202.119.66.100";
            Interface_E0_MAC = "17-10-22-ED-87-78";
            Interface_E1_MAC = "18-10-22-ED-87-78";
        }
        else {
            Switcher_Interface = "E2";
            Interface_E0_IP = "202.119.65.100";
            Interface_E1_IP = "202.119.66.101";
            Interface_E0_MAC = "19-10-22-ED-87-78";
            Interface_E1_MAC = "20-10-22-ED-87-78";
        }
    }

    //与交换机进行握手
    private void HandShake() throws IOException {
//        boolean isConnected = Socket_Ex.isConnected();
//        System.out.println(isConnected);
        System.out.println("路由器" + Router_Sym + "握手成功。");
        OutputStream outputStream = Socket_Ex.getOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        BufferedReader reader = new BufferedReader(new InputStreamReader(Socket_Ex.getInputStream()));
        byte Frame_type = (byte)3;
        byte[] Interface = Switcher_Interface.getBytes();
        byte[] MAC = MacToByte(Interface_E0_MAC);
//        byte[]  byteIP = ipToByteArray(Host_IP);
        dataOutputStream.write(Frame_type);
        dataOutputStream.write(Interface);
        dataOutputStream.write(MAC);
//        dataOutputStream.write(byteIP);
        dataOutputStream.flush();
    }

    public static class MyWindow extends JFrame {
        private final JComboBox<String> comboBox;
        private final JTextArea textArea;
        private DefaultTableModel model;

        public void updateTableData() {
            model.setRowCount(0);
            String file_path;
            if(Router_Sym == 'I'){
                file_path = "src/Processes/I_ARP_Table.ser";
            }
            else {
                file_path = "src/Processes/J_ARP_Table.ser";
            }
            for (String key : readHashMapFromFile(file_path).keySet()) {
                model.addRow(new Object[]{key, readHashMapFromFile(file_path).get(key)});
            }
            model.fireTableDataChanged();
        }
        public void addData(String key, String value) {
            String file_path;
            if(Router_Sym == 'I'){
                file_path = "src/Processes/I_ARP_Table.ser";
            }
            else {
                file_path = "src/Processes/J_ARP_Table.ser";
            }
            readHashMapFromFile(file_path).put(key, value);
            updateTableData();
        }

        public MyWindow(Router router) {
            myWindow = this;
            JFrame.setDefaultLookAndFeelDecorated(true);
            // 设置窗口属性
            setTitle("路由器");
            setSize(550, 300);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            // 创建下拉框
            String[] options = {"I", "J"};
            comboBox = new JComboBox<>(options);

            // 创建按钮
            JButton button = new JButton("启动路由器");
            button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String option = (String) comboBox.getSelectedItem();
                    // 在文本框中显示结果
//                    textArea.append("Option selected: " + option + "\n");
                    Router_Sym = option.charAt(0);
                    new Thread(()->{
                        try {
                            System.out.println("路由器" + Router_Sym + "开始运行...");
                            router.StartRouter(router);
                        } catch (IOException ex) {
                            throw new RuntimeException(ex);
                        }
                    }).start();
                }
            });

            // 创建文本框
            textArea = new JTextArea(10, 30);
            textArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textArea);
            JLabel label_Choose_Switcher = new JLabel("     请选择要启动的路由器：");
            JLabel ARP_Label = new JLabel("ARP高速缓存表      ");

            model = new DefaultTableModel(new Object[]{"Key", "Value"}, 0);
            model.addRow(new Object[]{"   IP地址", "            MAC地址"});

            // 将哈希表数据添加到表格模型中
            JTable table = new JTable(model);
            TableColumnModel columnModel = table.getColumnModel();
            columnModel.getColumn(0).setPreferredWidth(110);
            columnModel.getColumn(1).setPreferredWidth(135);


            // 添加组件到窗口
            JPanel panel = new JPanel();
            panel.add(ARP_Label);
            panel.add(label_Choose_Switcher);
            panel.add(comboBox);
            panel.add(button);
            JPanel panel_Table = new JPanel();
            panel_Table.add(table);

            add(panel, BorderLayout.NORTH);
            add(panel_Table, BorderLayout.WEST);
            add(scrollPane, BorderLayout.CENTER);
            Host.JTextAreaOutputStream out = new Host.JTextAreaOutputStream(textArea);
            System.setOut(new PrintStream(out));//设置输出重定向

            // 显示窗口
            setVisible(true);
        }
    }


    public void StartRouter(Router router) throws IOException {
        router.SetRouter();
        Socket socket_Between;
        //每次启动都清空路由器的ARP表
        if(Router_Sym == 'I'){
            clearFile("src/Processes/I_ARP_Table.ser");
            Socket_Ex = new Socket("localhost", 9998);
            socket_Between = new Socket("localhost", 8888);
        }
        else {
            clearFile("src/Processes/J_ARP_Table.ser");
            Socket_Ex = new Socket("localhost", 9997);
            socket_Between = new Socket("localhost", 8888);
        }
        router.HandShake();
        final PipedOutputStream output = new PipedOutputStream();
        final PipedInputStream  input  = new PipedInputStream(output);
        new RouterReadServer(Socket_Ex, socket_Between, input, output, 1).start();
        new RouterReadServer(Socket_Ex, socket_Between, input, output, 2).start();
        new RouterReadPipe(Socket_Ex, socket_Between , input, output).start();
    }

    public static void main(String[] args) throws IOException {
        Router router = new Router();
        new MyWindow(router);
    }
}




