package Processes;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import static Processes.FileOperation.clearFile;

public class Switcher {
    public static char Switcher_Sym;
    private String Router_IP;
    private Integer Router_Port;
    private String Switcher_IP;
    private Integer Switcher_Port;
    private ServerSocket Switcher_Socket;
    private List<Socket> listSocket = new ArrayList<>();
    public static volatile HashMap<String, String> Switcher_Table = new HashMap<>(); //交换机站表：接口号-源MAC地址
    public Switcher() {
    }

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

    public static class MyWindow extends JFrame {
        private final JComboBox<String> comboBox;
        private final JTextArea textArea;

        public MyWindow(Switcher switcher) {
            JFrame.setDefaultLookAndFeelDecorated(true);
            // 设置窗口属性
            setTitle("交换机");
            setSize(400, 300);
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setLocationRelativeTo(null);

            // 创建下拉框
            String[] options = {"M", "N"};
            comboBox = new JComboBox<>(options);

            // 创建按钮
            JButton button = new JButton("启动交换机");
            button.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String option = (String) comboBox.getSelectedItem();
                    // 在文本框中显示结果
//                    textArea.append("Option selected: " + option + "\n");
                    Switcher_Sym = option.charAt(0);
                    new Thread(()->{
                        try {
                            System.out.println("交换机" + Switcher_Sym + "开始运行...");
                            switcher.start();
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
            JLabel label_Choose_Switcher = new JLabel("请选择要启动的交换机：");

            // 添加组件到窗口
            JPanel panel = new JPanel();
            panel.add(label_Choose_Switcher);
            panel.add(comboBox);
            panel.add(button);

            add(panel, BorderLayout.NORTH);
            add(scrollPane, BorderLayout.CENTER);
            Host.JTextAreaOutputStream out = new Host.JTextAreaOutputStream(textArea);
            System.setOut(new PrintStream(out));//设置输出重定向

            // 显示窗口
            setVisible(true);
        }
    }





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

    public void start() throws IOException {
        Switcher switcher = new Switcher();

        if(Switcher_Sym == 'M'){
            switcher.Switcher_Socket = new ServerSocket(9998);
            clearFile("src/Processes/MTable.ser");
        }
        else {
            switcher.Switcher_Socket = new ServerSocket(9997);
            clearFile("src/Processes/NTable.ser");
        }


        int i = 0;
        while(true){
            System.out.println("Waiting for the client to connect...");
            Socket now_socket = switcher.Switcher_Socket.accept();
            switcher.listSocket.add(now_socket);
//            System.out.println(switcher.listSocket);
            i++;
            new SwitcherMultiThreadProcess(now_socket, switcher.listSocket).start();
        }
    }




    public static void main(String[] args) throws IOException {
    Switcher switcher = new Switcher();
    MyWindow window = new MyWindow(switcher);


    }
}


