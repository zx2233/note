package learning.thread;


import java.io.IOException;

/**
 * @author xuan
 * @date 2020/5/21 10:44
 */

public class ResponsiveUI extends Thread {
   private static volatile double d=1;
    private static volatile double x=0;
   public ResponsiveUI(){
       setDaemon(true);
       start();
   }
   @Override
   public void run(){
       while (true){
           d=x;
       }
   }

    public static void main(String[] args) throws IOException {
        new ResponsiveUI();
        System.in.read();
        ResponsiveUI.x=10;
        System.out.println(d);
    }
}
