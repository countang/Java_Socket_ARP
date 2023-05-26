package Processes;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;


public class RouterTrans {
    private ServerSocket Transit_Socket;
    private static final int bufferSize = 8092;
    private List<Socket> listSockets = new ArrayList<>();
    private int i = 0;

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

    private void Transit_Between(Integer port) throws IOException {
        Transit_Socket  =new ServerSocket(port);
        while (true){
//等待客户端的连接
            Socket socket_now = Transit_Socket.accept();
            listSockets.add(socket_now);
            System.out.println(listSockets.get(i));
            i++;
            //每当有一个客户端连接进来后，就启动一个单独的线程进行处理
            new Thread(new Runnable() {
                @Override
                public void run() {
//获取输入流,并且指定统一的编码格式
                    BufferedInputStream ois = null;
                    BufferedOutputStream oos = null;
                    try {
                        ois = new BufferedInputStream(socket_now.getInputStream());
                        oos = new BufferedOutputStream(socket_now.getOutputStream());
                        while(true){
                            byte[] by = new byte[bufferSize];
                            int res = 0;
                            res = ois.read(by);
                            if(res <= 0)
                                res = 0;
                            BroadCast(socket_now, by, res);
                        }
                    }catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    public static void main(String[] args) throws IOException {
        RouterTrans server = new RouterTrans();
        server.Transit_Between(8888);
    }

}
